from subprocess import Popen, PIPE
from collections import Counter
from datetime import datetime
import ipaddress
import logging
import json
import re
import os

# Pattern to help reduce non-error messages that are getting passed to
# stderr in the run command
_NON_ERROR_PATTERN = re.compile("reading from (?:.*?)file .*|input file:.*")
_WIRESHARK_TOOL_PATTERN = re.compile("Capinfos (?:\(Wireshark\) )?([0-9]+\.[0-9]+\.[0-9]+).*")
_SUDO_WARNING = re.compile("Running as user \"root\" and group \"root\". This could be dangerous.")
_MISSING_TOOL_PATTERN = re.compile(".*?which: no .*? in \(.*?\)")
_MIN_TOOL_VERSION = (1, 10, 2)


def get_version_tuple(version_str):
    split_version = version_str.split(".")
    return tuple(map(int, split_version))


class ExternalToolError(Exception):
    def __init__(self, msg):
        self.message = msg

    def __str__(self):
        return repr(self.message)


class InstantiationError(Exception):
    def __init__(self, msg):
        self.message = msg

    def __str__(self):
        return repr(self.message)


class PCAP:
    tool_version = (0, 0, 0)
    tool_version_str = None

    ##################################################
    # __init__
    ##################################################
    def __init__(self, filename):
        self.filepath = filename
        self.file_type = ""
        self.packet_count = 0
        self.file_size = 0
        self.capture_duration = 0
        self.start_time = 0
        self.end_time = 0
        self.strict_time_order = False
        self.raw_metadata = []

        try:
            self.parse_metadata()

        except ExternalToolError as e:
            raise InstantiationError(e.message)

    ##################################################
    # __init__
    ##################################################
    def __eq__(self, other):
        return (self.filepath == other.filepath) and \
               (self.packet_count == other.packet_count) and \
               (self.file_size == other.file_size) and \
               (self.capture_duration == other.capture_duration) and \
               (self.start_time == other.start_time) and \
               (self.end_time == other.end_time)

    ##################################################
    # run_command
    ##################################################
    @staticmethod
    def run_command(cmd_array):
        """
        Function to run the calls to the external libraries.

        @param cmd_array: array of command arguments
        @type cmd_array: list
        @return: response from the external library
        @rtype: list
        """

        p = Popen(cmd_array, stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()

        if len(err) > 0:
            err = err.strip().decode()
            if _NON_ERROR_PATTERN.match(err):
                logging.debug('Call returned non error message: "%s"', err)

            elif _MISSING_TOOL_PATTERN.match(err):
                return None  # Return none so that we get the tool missing error rather than the exception message

            elif _SUDO_WARNING.match(err):
                pass

            else:
                logging.debug("SUBPROCESS ERROR: %s", str(err.strip().splitlines()))
                raise ExternalToolError(err)

        if len(out) > 0:
            response_data = out.decode().strip().splitlines()
            return response_data

        return

    ##################################################
    # verify_tools
    ##################################################
    @classmethod
    def verify_tools(cls):
        """
        Checks to make sure that the necessary tools are installed and accessible via the path.
        Also ensures that the tools meet the minimum version requirement.

        @return: Boolean representing whether all tools were found or not
        @rtype: bool
        """
        # The list of tools we use
        unix_tool_list = ['editcap', 'bittwiste', 'mergecap', 'capinfos', 'tcpdump', 'tshark', 'reordercap']
        win_tool_list = ['editcap', 'bittwiste', 'mergecap', 'capinfos', 'windump', 'tshark', 'reordercap']

        all_good = True

        if os.name == "nt":
            for tool in win_tool_list:
                try:
                    tool_path = cls.run_command(["where", tool])

                    if tool_path is None:
                        logging.error("Tool Missing: %s could not be located. Ensure it is accessible"
                                      " from your path and try again.", tool)
                        all_good = False

                except ExternalToolError as e:
                    logging.error("Exception thrown checking for the existence of %s: %s", tool, e.message)
                    all_good = False

        else:
            for tool in unix_tool_list:
                try:
                    tool_path = cls.run_command(["which", tool])

                    if tool_path is None:
                        logging.error("Tool Missing: %s could not be located. Ensure it is accessible"
                                      " from your path and try again.", tool)
                        all_good = False

                except ExternalToolError as e:
                    logging.error("Exception thrown checking for the existence of %s: %s", tool, e.message)
                    all_good = False

        if all_good:
            # Check which version they are using.
            # Note: We are using the first line output by the help command to get the version info.
            # The reason for this is that older versions do not have a version flag. Also, we assume
            # that the version of capinfos is the same version number for mergecap, tshark, editcap,
            try:
                version_line = cls.run_command(["capinfos", '-h'])
                match = _WIRESHARK_TOOL_PATTERN.match(version_line[0])

                # If there's no match here it will throw an exception
                version_str = match.group(1)
                logging.debug("Version String Found: %s", version_str)

                # Convert the version string to a tuple so it can be compared
                tool_version = get_version_tuple(version_str)
                if tool_version >= _MIN_TOOL_VERSION:
                    logging.debug("Located version is greater than or equal to the minimum (%s >= %s)",
                                  version_str, ".".join(map(str, _MIN_TOOL_VERSION)))

                    # Set the values for the class so we can use them later
                    cls.tool_version = tool_version
                    cls.tool_version_str = version_str

                else:
                    raise ExternalToolError("The version of wireshark tools is too old. This tool requires version {} "
                                            "at a minimum. Found version {}".format(_MIN_TOOL_VERSION, version_str))

            except (ExternalToolError, AttributeError) as e:
                logging.error("Exception thrown checking for version number. %s", e)
                all_good = False

        return all_good

    ##################################################
    # format_capinfo_pkt_count
    ##################################################
    @staticmethod
    def format_capinfo_pkt_count(raw_packet_ct):
        """
        Helper function to transform the packet count returned by capinfos into an integer value.
        This method assumes the -M flag was used in the capinfos call

        @param raw_packet_ct: the raw packet count from the capinfos call
        @type raw_packet_ct: str
        @return: the packet count as an integer or None
        @rtype: int | None
        """

        try:
            return int(raw_packet_ct)

        except ValueError:
            logging.error("%s is not a valid packet count", raw_packet_ct)
            raise

    ##################################################
    # format_capinfo_file_size
    ##################################################
    @staticmethod
    def format_capinfo_file_size(raw_file_size):
        """
        Helper function to transform the file size returned by capinfos into an integer value.
        This method assumes the -M flag was used in the capinfos call

        @param raw_file_size: the raw file size from the capinfos call. EX 1024 bytes
        @type raw_file_size: str
        @return: the file size as an int or None
        @rtype: int | None
        """
        try:
            raw_file_size = raw_file_size.strip()
            match = re.match("([0-9]*) bytes", raw_file_size)

            if match:
                return int(match.group(1))

            else:
                raise AttributeError("Input doesn't match expected pattern of '([0-9]*) bytes'")

        except AttributeError:
            logging.error("%s is not a valid file size", str(raw_file_size))
            raise

    ##################################################
    # format_capinfo_capture_duration
    ##################################################
    @staticmethod
    def format_capinfo_capture_duration(raw_duration):
        """
        Helper function to transform the capture duration returned by capinfos into an integer value.
        This method assumes the -M flag was used in the capinfos call

        @param raw_duration: the raw capture duration from the capinfos call. EX 10 seconds
        @type raw_duration: str
        @return: capture duration as a float or None
        @rtype: float | None
        """
        try:
            raw_duration = raw_duration.strip()
            match = re.match("([0-9.]*) (sec(onds)?)", raw_duration)

            if match:
                return float(match.group(1))

            else:
                raise AttributeError("Input doesn't match expected pattern of '([0-9.]*) (sec(onds)?)'")

        except AttributeError:
            logging.error("%s is not a valid duration", str(raw_duration))
            raise

    ##################################################
    # format_capinfo_start_end_time
    ##################################################
    @staticmethod
    def format_capinfo_start_end_time(raw_time):
        """
        Helper function to assure start/end times returned by capinfos are valid.
        This method assumes the -S flag was used in the capinfos call

        @param raw_time: time as # of seconds since epoch
        @type raw_time: str
        @return: number of seconds since the epoch
        @rtype: float | None
        """
        try:
            return float(raw_time)

        except ValueError:
            logging.error("%s is not a valid time format", raw_time)
            raise

    ##################################################
    # format_capinfo_start_end_time
    ##################################################
    @staticmethod
    def format_capinfo_strict_time_order(raw_time_order):
        """
        Helper function to determine whether or not the file is in strict time order.

        @param raw_time_order: Bool string indicating if strict time order is in place
        @type raw_time_order: str
        @return: True if the file is in strict time order.
        @rtype: bool
        """
        time_order = raw_time_order.strip().lower()
        return time_order == "true"

    ##################################################
    # get_time_as_string
    ##################################################
    @staticmethod
    def get_time_as_string(decimal_time):
        """
        Helper function to format the start and end times in a more human readable fashion.

        @param decimal_time: start or end time as a decimal
        @type decimal_time: float
        @return: start or end time as a date string
        @rtype string | None
        """
        try:
            # Convert to an actual date/time
            return str(datetime.fromtimestamp(decimal_time))

        except (ValueError, TypeError) as err:
            logging.error(str(err))
            raise

    ##################################################
    # get_time_as_timestamp
    ##################################################
    @staticmethod
    def get_time_as_timestamp(decimal_time):
        """
        Return the time as a timestamp
        @param decimal_time: time as a decimal
        @type decimal_time: float
        @return: the time as a timestamp
        """
        return datetime.fromtimestamp(decimal_time)

    ##################################################
    # parse_metadata
    ##################################################
    def parse_metadata(self):
        """
        Function to call the capinfos command and parse the results into their respective variables.
        Definitions taken from capinfos man-pages
            - E{-}c: Displays the number of packets in the capture file.
            - E{-}s: Displays the size of the file, in bytes. This reports the size of the capture file itself.
            - E{-}u: Displays the capture duration, in seconds.
            - E{-}e: Displays the end time of the capture.
            - E{-}a: Displays the start time of the capture.
            - E{-}M: Print raw numeric data instead of data with SI suffixes ie 10,000 instead of 10k
            - E{-}S: Display the start and end times as seconds since January 1, 1970

        @return: None
        """

        # Capinfos call example
        # arendelle:AttackFiles cey$ capinfos -c -s -u -e -a -M -S attack1_pdf.pcap
        # File name:           attack1_pdf.pcap
        # Number of packets:   10
        # File size:           1924 bytes
        # Capture duration:    11.930185 seconds
        # First packet time:   1221305369.142674
        # Last packet time:    1221305381.072859

        metadata = self.run_command(["capinfos", '-t', '-c', '-s', '-u', '-e', '-a', '-o', '-M', '-S', self.filepath])

        if metadata is None:
            raise ExternalToolError("Capinfos failed to retrieve data for %s", self.filepath)

        # Save the raw return value so if an error occurs we can see what was returned.
        self.raw_metadata = metadata

        # Populate into a temp dictionary.
        temp = {}
        for option in metadata:
            # Split on the first colon only.
            # Hopefully this will eliminate need for special cases for Windows file paths
            key_value = option.split(":", 1)
            key = key_value[0].lower()
            val = key_value[1]
            temp[key] = val

        # Now that we have the data lets assign it!
        try:
            if "file type" in temp:
                self.file_type = temp["file type"].strip()

            if "number of packets" in temp:
                self.packet_count = self.format_capinfo_pkt_count(temp["number of packets"])

            if "file size" in temp:
                self.file_size = self.format_capinfo_file_size(temp["file size"])

            if "capture duration" in temp:
                self.capture_duration = self.format_capinfo_capture_duration(temp["capture duration"])

            # For the next two we have two possible key's due to a change in capinfos.
            if "first packet time" in temp:
                self.start_time = self.format_capinfo_start_end_time(temp["first packet time"])

            elif "start time" in temp:
                self.start_time = self.format_capinfo_start_end_time(temp["start time"])

            if "last packet time" in temp:
                self.end_time = self.format_capinfo_start_end_time(temp["last packet time"])

            elif "end time" in temp:
                self.end_time = self.format_capinfo_start_end_time(temp["end time"])

            if "strict time order" in temp:
                self.strict_time_order = self.format_capinfo_strict_time_order(temp["strict time order"])

        except Exception as e:
            logging.error("Problem parsing capinfos metadata for file %s", self.filepath)
            logging.debug("Returned Metadata: %s", str(metadata))
            raise InstantiationError(str(e))

    ##################################################
    # get_metadata
    ##################################################
    def get_raw_metadata(self):
        """
        Mainly to be used for testing purposes, this method returns the data as is with no conversions.
        Specifically the start and end times are given in seconds since the epoch rather than being converted
        into a more readable form.

        @return: dictionary containing all metadata in its pure form. IE times are not converted
        @rtype: dict
        """
        return {'file_name': self.filepath,
                'file_type': self.file_type,
                'packet_count': self.packet_count,
                'file_size': self.file_size,
                'capture_duration': self.capture_duration,
                'start_time': self.start_time,
                'end_time': self.end_time,
                'strict_time_order': self.strict_time_order
                }

    ##################################################
    # get_metadata
    ##################################################
    def get_metadata(self):
        """
        Gathers all the metadata into a dict so it can be used as JSON

        @return: dictionary containing all metadata
        @rtype: dict
        """
        return {'file_name': self.filepath,
                'file_type': self.file_type,
                'packet_count': self.packet_count,
                'file_size': self.file_size,
                'capture_duration': self.capture_duration,
                'start_time': self.get_time_as_string(self.start_time),
                'end_time': self.get_time_as_string(self.end_time),
                'strict_time_order': self.strict_time_order
                }

    ##################################################
    # get_metadata_as_str
    ##################################################
    def get_metadata_as_str(self):
        """
        Gathers all the metadata and returns it as a JSON string

        @return: a string containing the metadata in JSON form
        @rtype: str
        """
        metadata = self.get_metadata()
        return json.dumps(metadata, indent=3)

    ##################################################
    #
    ##################################################
    def log_metadata(self):
        """
        Writes the metadata out to the log
        @return: None
        @rtype: None
        """
        logging.info("")
        logging.info("File Name: %s", self.filepath)
        logging.info("File Type: %s", self.file_type)
        logging.info("Packet Count: %s", str(self.packet_count))
        logging.info("File Size: %s", str(self.file_size))
        logging.info("Duration: %s", str(self.capture_duration))
        logging.info("Start Time: %s", self.get_time_as_string(self.start_time))
        logging.info("End Time: %s", self.get_time_as_string(self.end_time))
        logging.info("Strict Time Order: %s", str(self.strict_time_order))
        logging.info("")

    ##################################################
    # shift_time
    ##################################################
    def shift_time(self, outfile, seconds):
        """
        Shifts the time of the pcap file this object represents and writes it to a new pcap file.

        @param outfile: Path to where the new pcap should be written
        @type outfile: str
        @param seconds: How many seconds the pcap should be shifted.
        @type seconds: float
        @return: None
        @rtype: None
        """
        try:
            logging.info("Shifting time in PCAP by %.6f seconds", seconds)

            # editcap -F <file_type> -t <seconds> <infile> <outfile>
            self.run_command(["editcap", '-F', 'pcap', '-t', str(seconds), self.filepath, outfile])

        except (TypeError, RuntimeError, ExternalToolError) as err:
            logging.error("Failed to shift pcap time. Reason: %s", str(err))
            raise

    ##################################################
    # merge_pcaps
    ##################################################
    def merge_pcaps(self, to_merge, output_path):
        """
        Merge this pcap with another and write to a file.

        @param to_merge: The PCAP instance you would like to merge this instance with
        @type to_merge: PCAP
        @param output_path: The path to where you would like the newly merged PCAP file to be written
        @type output_path: str
        @return:
        @rtype:
        """
        # TODO eventually may need to remove -F pcap in order to allow pcapng.
        # Note: Rather than remove it, in order to remain backwards compatible leave the flag
        # and just change the following type to be 'pcapng'. Should be supported in both, but untested.
        try:
            self.run_command(['mergecap', '-F', 'pcap', '-w', output_path, self.filepath, to_merge.filepath])

        except (AttributeError, ExternalToolError) as e:
            logging.error("Failed to Merge. Reason: %s", str(e))
            raise

    ##################################################
    # get_network_ips
    ##################################################
    def get_network_ips(self, network_list):
        """
        Collects all valid network ips for the file.
        @param network_list:list of networks to check against.
        @type network_list:list
        @return: list of valid ips.
        @rtype: Counter
        """
        all_ips = Counter()
        net_ips = Counter()

        # Build our command to pull only packets that have a src or dst that match our networks.
        command = ['tcpdump', '-tnr', self.filepath]

        # Setup ip check for non VLAN traffic
        for net in network_list:
            net_str = str(net)

            # Append the or if it's not the first one.
            if len(command) != 3:
                command.append("or")

            command.append("net")
            command.append(net_str)

        # Setup ip check for VLAN traffic
        command.append("or")
        vlan_filter_str = "(vlan and "
        for i, net in enumerate(network_list):
            net_str = str(net)

            # If this is the first network in the list we need to open our parenthesis
            if i == 0:
                vlan_filter_str += "(net {}".format(net_str)

            # If we're at the end of our list and the list has more than 1 network
            # Add the current network and close the parenthesis
            elif i == len(network_list) - 1:
                vlan_filter_str += " or net {}))".format(net_str)

            # If we're in the middle of the list, just add the current network
            else:
                vlan_filter_str += " or net {}".format(net_str)

            # If the list only has 1 network close off the parenthesis.
            # (The network was added in first if statement)
            if len(network_list) == 1:
                vlan_filter_str += "))"

        command.append(vlan_filter_str)

        # Run the command
        logging.debug("Get Network IPs Command: {}".format(" ".join(command)))
        data_strs = self.run_command(command)

        # Get the src & dst addresses for packets that match the networks
        if not data_strs:
            logging.error("No packets matching the provided networks were found.")
            return None

        for packet in data_strs:
            match_obj = re.match("IP ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?:\.[0-9]+)? > ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?:\.[0-9]+)?: .*", packet)
            if match_obj:
                all_ips[match_obj.group(1)] += 1
                all_ips[match_obj.group(2)] += 1

        # TODO implement IPV6!

        # if no networks were provided return the counter as is.
        if not network_list:
            logging.info("No networks provided, so defaulting to all.")
            return all_ips

        # If networks were provided, lets whittle it down to only ips that match our networks
        # Note: This is done after all extractions so each ip is only done once.
        for address in all_ips:
            try:
                # convert to an ipaddress instance
                ip = ipaddress.ip_address(str(address))

                # Check if the address is in one of the networks
                for net in network_list:
                    if ip in net:
                        net_ips[str(ip)] = all_ips[address]

            except Exception as e:
                logging.error("Error converting %s to ipaddress instance. %s", address, e.message)

        return net_ips

    ##################################################
    # swap_ips
    ##################################################
    def swap_ips(self, outfile, old_ip, new_ip):
        """
        Replace an ip with a new ip everywhere it occurs in the pcap and write back out to a file.

        @param outfile: The location to write to.
        @type outfile: str
        @param old_ip: The ip that should be replaced
        @type old_ip: str
        @param new_ip: The new ip to insert
        @type new_ip: str
        @return: None
        @rtype: None
        """

        try:
            # bittwiste -I <infile> -O <outfile> -T ip -s <old_ip>, <new_ip> -d <old_ip>,<new_ip>
            self.run_command(['bittwiste', '-I', self.filepath, '-O', outfile, '-T', 'ip', '-s',
                              "{},{}".format(old_ip, new_ip), '-d', "{},{}".format(old_ip, new_ip)])

        except Exception as e:
            logging.error("Failed to swap ips. Reason: %s", str(e))
            raise

    ##################################################
    # swap_macs
    ##################################################
    def swap_macs(self, outfile, old_mac, new_mac):
        """
        Replace an mac with a new mac everywhere it occurs in the pcap and write back out to a file.

        @param outfile: The location to write to.
        @type outfile: str
        @param old_mac: The mac that should be replaced
        @type old_mac: str
        @param new_mac: The new mac to insert
        @type new_mac: str
        @return: None
        @rtype: None
        """

        try:
            # bittwiste -I <infile> -O <outfile> -T eth -s <old_mac>,<new_mac> -d <old_mac>,<new_mac>
            self.run_command(['bittwiste', '-I', self.filepath, '-O', outfile, '-T', 'eth',
                              '-s', "{},{}".format(old_mac, new_mac), '-d', "{},{}".format(old_mac, new_mac)])

        except Exception as e:
            logging.error("Failed to swap macs. Reason: %s", str(e))
            raise

    ##################################################
    # get_mac_for_ip
    ##################################################
    def get_mac_for_ip(self, ip):
        """
        Return the mac address for the given ip

        @param ip: The ip you want the mac address for
        @type ip: str
        @return: The mac address associated with that IP
        @rtype: str | None
        """
        mac_addrs = Counter()

        # Filter on the ip as the source
        # tshark -Y ip.src==<ip> -r <infile> -T fields -e eth.src
        src_macs = self.run_command(['tshark', '-2', '-R', 'ip.src=={}'.format(ip), '-r', self.filepath, '-T',
                                     'fields', '-e', 'eth.src'])
        if src_macs:
            for mac in src_macs:
                mac_addrs[mac] += 1

        # Filter of the ip as the destination
        # tshark -Y ip.src==<ip> -r <infile> -T fields -e eth.src
        dst_macs = self.run_command(['tshark', '-2', '-R', 'ip.dst=={}'.format(ip), '-r', self.filepath, '-T',
                                     'fields', '-e', 'eth.dst'])
        if dst_macs:
            for mac in dst_macs:
                mac_addrs[mac] += 1

        if not mac_addrs:
            return

        elif len(mac_addrs) > 1:
            # logging.warning("More than one mac address was found for this IP. Returning the most common mac found")
            logging.debug("Associated MAC Addresses: %s", str(mac_addrs))
            return mac_addrs.most_common(1)[0][0]

        else:
            return list(mac_addrs.keys())[0]

    ##################################################
    # convert_to_pcap
    ##################################################
    def convert_to_pcap(self, output_path):
        """
        Convert a pcapng file to a pcap file.

        @param output_path: destination for new pcap file
        @type output_path: str
        @return: None
        @rtype: None
        """
        try:

            # editcap -F <file_type> -t <seconds> <infile> <outfile>
            self.run_command(["editcap", '-F', 'pcap', self.filepath, output_path])

        except:
            logging.error("Failed to convert %s from pcapng to pcap", self.filepath)


if __name__ == "__main__":
    try:
        PCAP.verify_tools()
        pcap = PCAP("../testdata/AttackFiles/attack1_pdf.pcap")

    except RuntimeError as error:
        print("The following error occurred. Preparing to exit: %s", str(error))
        exit(1)
