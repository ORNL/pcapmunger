from __future__ import print_function
from functools import partial
from multiprocessing import Manager, Pool
import multiprocessing as mp
from datetime import datetime
from pcap import PCAP, ExternalToolError, InstantiationError
from defusedxml.ElementTree import parse
from xml.etree.ElementTree import ElementTree, Element, ParseError
from random import SystemRandom
import ipaddress
import argparse
import logging
import logging.handlers
import errno
import glob
import json
import sys
import os
import shutil
import pandas as pd

import traceback

DEFAULT_PADDING = 15.0

__H5_DATA__ = None


class ModifiedParser(argparse.ArgumentParser):
    """
    Overrides argparse's ArgumentParser in order to write both the error message
    and the help message out to stderr before exiting.
    """
    def error(self, message):
        sys.stderr.write('error:%s\n' % message)
        self.print_help(sys.stderr)
        sys.exit(1)


def listener_configurer(configurations):
    """
    Configure logging for our logging process

    @param configurations: The configuration file arguments
    @type configurations: dict
    """
    setup_logging(configurations)


def listener_process(queue, configurer, conf_values):
    """
    Listening process to handle logs coming from process pool.

    @param queue: queue object for log messages
    @type queue: Queue
    @param configurer: function to call to perform configuration
    @type configurer: function
    @param conf_values:The configuration file arguments
    @type conf_values: dict
    """
    # Taken from https://docs.python.org/3.9/howto/logging-cookbook.html
    configurer(conf_values)
    while True:
        try:
            #record = queue.get()
            record = None
            if record is None:  # We send this as a sentinel to tell the listener to quit.
                break
            logger = logging.getLogger(record.name)
            logger.handle(record)  # No level or filter logic applied - just do it!
        except Exception:
            import sys, traceback
            print('Whoops! Problem:', file=sys.stderr)
            traceback.print_exc(file=sys.stderr)


def process_configurer(logging_queue):
    """
    Configuration function for the processes spawned by the pool

    @param logging_queue: queue object for log messages
    @type logging_queue: Queue
    """
    root = logging.getLogger()

    # Doing this to prevent duplicate log entries.
    found_queue_handler = False
    for handler in root.handlers:
        if isinstance(handler, logging.handlers.QueueHandler):
            found_queue_handler = True
            break

    if not found_queue_handler:
        queue_handler = logging.handlers.QueueHandler(logging_queue)  # Just the one handler needed
        root.addHandler(queue_handler)
        root.setLevel(logging.DEBUG)


def setup_logging(args):
    """
    Sets up the logging for the program. It includes 3 loggers: a console logger and two file loggers (One generic and
    one for progress status).

    @param args: The configuration file arguments
    @type args: dict
    @return: Whether the setup was successful
    @rtype: bool
    """
    try:

        # Check if the provided log directory is valid. If not set to current directory
        if "LogDir" not in args:
            sys.stderr.write("No log directory provided. Defaulting to current directory\n")
            logdir = "."

        else:
            logdir = args["LogDir"]
            if not os.path.isdir(logdir):
                # If the provided dir doesn't exist, write the logs to the current directory
                sys.stderr.write("Invalid log directory path: {}. Defaulting to current directory\n".format(logdir))
                logdir = '.'

        args["LogDir"] = logdir

        mung_log = os.path.abspath(os.path.join(logdir, "pcap_munging.log"))

        # Check if the provided log level is valid. If not default to INFO
        if "LogLevel" not in args:
            sys.stderr.write("No log level provided in configuration file. Defaulting to INFO.\n")
            numeric_level = logging.INFO
        else:
            numeric_level = getattr(logging, args["LogLevel"].upper(), None)
            if not isinstance(numeric_level, int):
                sys.stderr.write("Invalid log level: {}. Defaulting to INFO.\n".format(args["LogLevel"]))
                numeric_level = logging.INFO

        # Set up the various log handlers.
        logger = logging.getLogger('')
        logger.setLevel(logging.DEBUG)  # Set to debug so we can choose any level of output for the handlers

        # Set up a timed rotating file handler for the main log file.
        general = logging.handlers.TimedRotatingFileHandler(mung_log, when='midnight', backupCount=20)
        general.setLevel(numeric_level)
        general_formatter = logging.Formatter('[%(asctime)s] %(processName)s - %(levelname)s - %(funcName)s - %(message)s', '%Y-%m-%d %H:%M:%S')
        general.setFormatter(general_formatter)

        # Set up the console logger
        console = logging.StreamHandler()
        console.setLevel(logging.WARNING)
        formatter = logging.Formatter('%(processName)s - %(funcName)s - %(levelname)s - %(message)s')
        console.setFormatter(formatter)

        # Add the handlers to our logger
        logger.addHandler(general)
        logger.addHandler(console)

    except IOError as e:
        logging.critical("Failed to configure logging for the following reason: %s", str(e.strerror))
        raise

    except Exception as e:
        logging.critical("Failed to configure logging for the following reason: %s", str(e))
        raise

    else:
        logging.info("Logging set up Sucessfully.")
        logging.info("Log files writing to %s with a level of %s.", os.path.abspath(logdir),
                     logging.getLevelName(numeric_level))


def calculate_needed_timeshift(attack_pcap, target_pcap, padding):
    """
    Calculate how far the attack file needs to be shifted in order to fit into the target file

    @param attack_pcap: PCAP instance representing the attack file
    @type attack_pcap: PCAP
    @param target_pcap: PCAP instance representing the target file
    @type target_pcap: PCAP
    @param padding: How much space (timewise) should be guaranteed at the beginning and end of the target file
    @type padding: int | float
    @return: How far the attack file needs to be shifted
    @rtype: float
    """

    # Get time difference in seconds. This offset represents the amount of time the attack pcap
    # needs to be shifted in order to start at exactly the same time as the target pcap
    initial_offset = target_pcap.start_time - attack_pcap.start_time

    # Find the last possible starting point to insert our attack and still maintain the end time.
    # I.E., if the attack duration is 10 seconds and the target duration is 60 seconds, we know
    # the last possible insertion point is 50 seconds into the target file. The remaining 10 seconds
    # are needed to insert the rest of the attack and still maintain the end time.
    # If padding is not set to 0, this is also accounted for. So in the preceding example, assuming
    # a 2 second padding, the last possible insertion point is 48 seconds into the target file.
    max_range = target_pcap.capture_duration - attack_pcap.capture_duration - padding

    # Safety check for if max range is less than the amount of padding. Not performing this check resulted
    # in an error where the start and end times of the new file were wrong.
    if max_range < padding:
        logging.error("Target file not large enough for attack with a padding of %f seconds", padding)
        return None

    # Select a random floating point number between x and y where x is the amount of padding we want
    # and y is the last possible starting point that will still allow for the entire attack and the requisit padding
    # without altering the end time.
    # Note: random.uniform is not order dependent which caused the need for the max_range < padding check above
    #       i.e. random.uniform(2, .8) == random.uniform(.8, 2)
    # The random number selected will be the insertion point for the first packet of the attack
    additional_offset = SystemRandom().uniform(padding, max_range)

    # The total shift the attack pcap will undergo.
    return initial_offset + additional_offset


def check_args(conf_obj, run_type):
    """
    Check to see if the values provided in the configuration file are valid

    @param conf_obj: dictionary containing the contents of the json configuration file
    @type conf_obj: dict
    @param run_type: Whether the munger is being run on training or validation data.
    @type run_type: str
    @return: True or False depending on the success or failure of the check
    @rtype: bool
    """

    # First check if it has any values at all. If not return right off the bat. No point in doing all checks
    if not conf_obj:
        logging.error("Configuration file provided none of the required items")
        return

    global __H5_DATA__  # Bind variable to outer scope.
    all_good = True
    net_addrs = []

    # We expect an Attack Directory, Raw Target Directory, and an Output Directory
    # The output directory is where Normal_Attack will reside

    if run_type == "training":
        required = ["RawTrainingSamples", "SelectedNormalSamples", "MungedTrainingSamples"]

    else:
        required = ["RawValidationSamples", "SelectedNormalSamples", "MungedValidationSamples"]

    missing = [required_key for required_key in required if required_key not in conf_obj]

    if missing:
        logging.error("Configuration file missing the following required elements: %s", json.dumps(missing))
        all_good = False

    else:
        # Check the attack directory
        attack_dir = conf_obj["RawTrainingSamples"] if run_type == "training" else conf_obj["RawValidationSamples"]
        if not os.path.isdir(attack_dir):
            logging.error("The provided attack directory does not exists: %s", attack_dir)
            all_good = False

        # Check the Target Directory
        if not os.path.isdir(conf_obj["SelectedNormalSamples"]):
            logging.error("The provided raw pcap directory does not exists: %s",
                          conf_obj["SelectedNormalSamples"])
            all_good = False

        # Look for an H5 File in the raw directory.
        else:
            parent = os.path.dirname(conf_obj["SelectedNormalSamples"])
            glob_str = os.path.join(parent, "*.h5")
            h5_files = glob.glob(glob_str)

            if not h5_files:
                logging.info("No H5 file found. Target Selection will default to making capinfos calls.")

            elif len(h5_files) > 1:
                logging.warning("Multiple H5 files found. Target Selection will default to making capinfos calls.")

            else:
                h5_file = h5_files[0]
                logging.info("H5 file detected: %s. Target Selection will utilize file.", h5_file)
                try:
                    with pd.HDFStore(h5_file) as store:
                        __H5_DATA__ = store['df']
                except:
                    logging.error("Failed to collect h5 data from file. Reverting to capinfos calls")

        # Setup our output directory
        root = conf_obj["MungedTrainingSamples"] if run_type == "training" else conf_obj["MungedValidationSamples"]
        attack_output_folder = os.path.join(root, "Normal_Attack")
        try:
            logging.debug("Attempting to make output folder %s", attack_output_folder)
            os.makedirs(attack_output_folder)
            conf_obj["OutputPath"] = attack_output_folder

        except OSError as e:
            if e.errno == errno.EEXIST:
                logging.debug("%s already exists.", attack_output_folder)
                conf_obj["OutputPath"] = attack_output_folder

            else:
                logging.error("Problem creating the desired output directory: %s. Reason: %s", root, str(e))
                all_good = False

        # Setup the directory to store our merged targets in, but only if things are ok so far.
        if all_good:
            merged_target_dir = os.path.join(root, "merged_targets")
            try:
                logging.debug("Attempting to make merged_target folder %s", merged_target_dir)
                os.makedirs(merged_target_dir)
                conf_obj["MergedTargetPath"] = merged_target_dir

            except OSError as e:
                if e.errno != errno.EEXIST:
                    logging.error("Unable to create the merged_target directory %s. %s",
                                  merged_target_dir, e.strerror)
                    all_good = False

                else:
                    logging.debug("Merged target folder already exists")
                    conf_obj["MergedTargetPath"] = merged_target_dir

        # Perform checks for Source/Type. If they are not provided default to any/all
        if "Source" not in conf_obj:
            logging.info("No Source provided. Defaulting to all")
            conf_obj["Source"] = '*'

        if "Type" not in conf_obj:
            logging.info("No Type provided. Defaulting to all")
            conf_obj["Type"] = '*'

        # Check the value for how many times we should merge each attack. If not provided/bad default to 1
        try:
            conf_obj["NumMergesPerAttack"] = int(conf_obj["NumMergesPerAttack"])

        except ValueError:
            logging.warning("%s is not a valid value for the number of merges per attack. Defaulting to 1.",
                            conf_obj["NumMergesPerAttack"])
            conf_obj["NumMergesPerAttack"] = 1

        except KeyError:
            logging.warning("No value provided for the number of merges. Defaulting to 1.")
            conf_obj["NumMergesPerAttack"] = 1


    # Check the ip ranges.
    if "IPRanges" not in conf_obj:
        logging.error("No address ranges were provided in the configuration file.")
        all_good = False

    else:
        for net_range in conf_obj["IPRanges"]:
            try:
                network = ipaddress.ip_network(net_range)
                net_addrs.append(network)

            except ValueError as e:
                logging.error("Invalid Network Address (%s). Skipping for the following reason: %s",
                              net_range, str(e))

        if not net_addrs:
            logging.error("All provided network addresses were invalid")
            net_addrs = None
            all_good = False

    conf_obj["Networks"] = net_addrs

    # Check to see if a padding value was provided. If not, set to default
    # If they did ensure that the provided value is actually a number and convert the value to seconds ( We assume
    # the value provided is in ms)
    padding = DEFAULT_PADDING
    if "Padding" in conf_obj:
        try:
            p_ms = float(conf_obj["Padding"])
            padding = p_ms / 1000

        except ValueError as e:
            logging.error("Error with provided padding (%s). Defaulting to %s seconds", str(e), DEFAULT_PADDING)

    conf_obj["Padding"] = padding

    # If there was an error return False
    # Note this is done here rather than at each error in order to provide all errors to the user at once.
    return all_good


def ensure_data_longer_than_attack(attack_pcap, target_pcap, padding):
    """
    Checks if the target pcap is longer (in terms of time) than the attack pcap even with the provided padding

    @param attack_pcap: PCAP instance representing the attack file
    @type attack_pcap: PCAP
    @param target_pcap: PCAP instance representing the target file
    @type target_pcap: PCAP
    @param padding: How much space (timewise) should be guaranteed at the beginning and end of the target file
    @type padding: int | float
    @return: Boolean indicating if the target file is big enough to fit the entire attack
             file even with a certain amount of padding
    @rtype: bool
    """
    return attack_pcap.capture_duration + padding * 2 < target_pcap.capture_duration


def existing_mung_check(mung_folder, atk_basename):

    for root, dirnames, filenames in os.walk(mung_folder):
        for filename in filenames:
            if filename.startswith(atk_basename):
                return True

    return False


# In general we operate on the assumption that src is always attacker and  dest always the victim
def get_attack_info(xml_file):
    """
    Extracts attack info from the xml_file

    @param xml_file: The xml related to the attack file we are processing
    @type xml_file: str
    @return: the attack information
    @rtype: list
    """
    try:
        tree = parse(xml_file)

    except FileNotFoundError:
        raise

    except Exception as e:
        # For whatever reason this WILL NOT catch a ParseError no matter what I try. so I'm just going to catch
        # any exception that comes and raise a parse error myself.
        # I'm not 100% alone. It's stupid. It's ugly. I hate it. Here we are.
        # https://stackoverflow.com/questions/47917787/xml-etree-elementtree-parseerror-exception-handling-not-catching-errors
        # https://forum.kodi.tv/showthread.php?tid=282217
        raise ParseError(str(e))

    root = tree.getroot()

    # Get all filter nodes
    filters = root.findall(".//filter[@sourceIP][@destIP]")

    if not filters:
        raise AttributeError("No filters were found in the xml file")

    xml_filters = []
    for attack_filter in filters:
        # This may have extra info in it but not really a concern.
        #  No point in pulling data out to put in new dict to return.
        xml_filters.append(attack_filter.attrib)

    return xml_filters


def get_new_victims(old_vics, target_pcap, target_networks, used_ips):
    """
    Select a new victim from the target pcap

    @param old_vics: Set of the original victim ips
    @type old_vics: Set
    @param target_pcap: The target pcap that will be used in the munging
    @type target_pcap: PCAP
    @param target_networks: the list of networks to check selected ips against
    @type target_networks: list[IPv4Network| IPv6Network]
    @param used_ips: the list of ip previously selected for this attack file.
    @type used_ips: list
    @return: a mapping of old victims to new victims
    @rtype: dict
    """
    try:
        target_ips = target_pcap.get_network_ips(target_networks)

        if not target_ips:
            logging.error("Unable to obtain IPs for the provided networks")
            return

        if len(old_vics) > len(target_ips):
            raise NotImplementedError("No handling for attacks with more network IPs than the target PCAP")

        ip_list = list(target_ips.keys())
        ip_mapping = {}
        for ip in old_vics:
            if ip_list:
                selected = SystemRandom().choice(ip_list)
                if selected not in used_ips:
                    ip_mapping[ip] = selected
                    used_ips.append(selected)

                ip_list.remove(selected)
            else:
                # TODO do we need to evaluate the difference between used in this particular file and used across iterations?
                logging.warning("All available IPs from the target have been used. Re-using target IPs.")
                ip_list = target_ips.keys()
                used_ips = []

        return ip_mapping

    except Exception as e:
        logging.error("Error selecting new victim. %s", str(e))

    return


def get_pcap_file_data(filename):
    """
    Collects the duration, start and end times for the specified file using capinfos.

    @param filename: the filepath to the pcap to be checked.
    @type filename: str
    @return: duration, start time, end time
    @rtype: tuple
    """
    # TODO not sure if this is the best option. Has resulted in the target being instantiated twice. either need to go back to calling individually or somehow return the pcap. Leaning back toward a seperate call.
    pcap = new_pcap(filename)

    if pcap:
        duration = pcap.capture_duration
        start_tstamp = pcap.get_time_as_timestamp(pcap.start_time)
        end_tstamp = pcap.get_time_as_timestamp(pcap.end_time)

        return duration, start_tstamp, end_tstamp

    return

def get_pcaps_from_dir(dirpath, source='*', atk_type='*'):
    """
    Get all the pcaps in a given directory that match the source and type.
    If both are '*' then return all pcaps in the directory

    @param dirpath: path to the directory containing pcaps
    @type dirpath: string
    @param source: the source to check filenames against
    @type source: str
    @param atk_type: the type to check filenames against
    @type atk_type: str
    @return: all pcaps found in the specified directory
    @rtype: list
    """
    pcap_list = []
    extensions = ["pcap", "cap", "pcapng"]

    # if the source and type are set to any, return all files in the directory
    if source == '*' and atk_type == '*':
        logging.debug("Both Source and Type set to any. Collecting all pcap files in %s", dirpath)
        name_pattern = ""

    # Otherwise return only the files that match the users requirements
    else:
        logging.debug("Source: %s, Type: %s. Collecting files matching these filters in %s", source, atk_type, dirpath)
        name_pattern = "[[]{}[]][[]{}[]]".format(source, atk_type)

    for ext in extensions:
        filename = "{}*.{}".format(name_pattern, ext)
        glob_str = os.path.join(dirpath, filename)
        pcap_list.extend(glob.glob(glob_str))

    return pcap_list


def new_pcap(filename):
    """
    Creates a new PCAP instance for the given file and does the necessary Error checking

    @param filename: The file you want a PCAP instance for
    @type filename: str
    @return: The PCAP instance
    @rtype: PCAP
    """
    try:
        logging.debug("Creating PCAP instance for %s", filename)
        return PCAP(filename)

    except InstantiationError as e:
        logging.error("Unable to instantiate PCAP instance for %s. Reason for Failure: %s", filename, str(e))

    return


def re_order_pcap(unordered_pcap, ordered_pcap_path):
    logging.info("%s is not in strict time order. Attempting to re-order", unordered_pcap.filepath)

    try:
        PCAP.run_command(["reordercap", unordered_pcap.filepath, ordered_pcap_path])
        return new_pcap(ordered_pcap_path)

    except Exception as e:
        logging.error("Unable to re-order %s. %s", unordered_pcap.filepath, str(e))


def get_h5_data_for_file(filename):
    """
    Collects the duration, start and end times for the specified file from the h5 data file.

    @param filename: the file to get data for
    @type filename: str
    @return: duration, start time, end time
    @rtype: tuple
    """
    file_meta = __H5_DATA__[__H5_DATA__['filename'].str.contains(filename)]
    duration = float(file_meta['capture_duration_sec'].iloc[0])
    start_time = file_meta['first_packet_time'].iloc[0]
    end_time = file_meta['last_packet_time'].iloc[0]

    return duration, start_time, end_time


def get_target_metadata(target):
    """ Calls the appropriate function to collect the target metadata depending on whether or not we have an h5 file.

    @param target: filepath of pcap to be checked.
    @type target: str
    """
    if __H5_DATA__ is not None:
        try:
            # Lookup the filename in the h5 file
            # **NOTE** This sends only the filename and not the whole file path. This prevents issues when files move.
            return get_h5_data_for_file(os.path.basename(target))

        except IndexError:
            logging.error("Unable to find %s in h5 file.", target)

    else:
        return get_pcap_file_data(target)

    return


def check_target(attack_pcap, target_file, all_sorted_targets, bad_targets, merged_target_dir, networks, padding):
    """
    Selects a target file large enough to accommodate the attack file. If the selected file isn't large enough,
    it will merge targets together until it has generated on that is.

    @param attack_pcap: The attack pcap we want to mung
    @type attack_pcap: PCAP
    @param target_file: the target file to check
    @type target_file: str
    @param all_sorted_targets: the list of all targets in order
    @type all_sorted_targets: list
    @param bad_targets: the shared list of bad target files
    @type bad_targets: list
    @param merged_target_dir: the directory to write merged target files to
    @type merged_target_dir: str
    @param networks: list of valid networks
    @type networks: list
    @param padding: the amount of padding we need on either side of the attack
    @type padding: float
    @return: the selected target file, list of bad pcaps, and the list of used target files
    @rtype: tuple
    """
    errors = []  # A container for the files that cause problems.
    used_files = []  # A container for the files that are used to make up our target file.

    # Figure out the smallest possible duration that will be able to contain the attack
    min_duration = attack_pcap.capture_duration + padding * 2
    logging.debug("Minimum duration needed: %s", min_duration)

    for count in range(len(all_sorted_targets)):
        used_files[:] = []  # Clear our used files list.

        # First try the file that was chosen in the beginning.
        if count == 0:
            selected_target = target_file

        # Create a new randomized list of potential targets to choose from
        elif count == 1:
            try:
                potential_targets = SystemRandom().sample(all_sorted_targets, len(all_sorted_targets))
                potential_targets.remove(target_file)  # remove the file we already checked.

            except Exception as e:
                logging.error("Failed to perform random selection of target files. %s", str(e))
                return None, errors, used_files

        # If the file provided didn't work out we need to select a new base file.
        if count > 0:
            selected_target = potential_targets.pop()

            if selected_target in bad_targets:
                continue

        logging.debug("Selected potential target: %s", selected_target)

        # Get metadata for selected file
        target_data = get_target_metadata(selected_target)
        if target_data:
            selected_duration = target_data[0]
            selected_start = target_data[1]
            selected_end = target_data[2]

        else:
            # If we failed to get the data, add it to the bad files list and try to select a new file
            logging.error("Failed to gather data for selected file. Picking new file.")
            errors.append(("Bad Target Files", "Bad Duration", selected_target))
            bad_targets.append(selected_target)
            continue

        # TODO need to check if it has a valid ip here.Probably a quick check with tcpdump or tshark
        # the old way of doing this doesn't work as we arent making it a pcap instance from the start!

        # if not has_valid_ip:
        #     logging.info("Candidate did not have any valid ips for the provided networks.")
        #     bad_pcaps.append((selected_target, "No Valid Ips"))

        # if the file isn't large enough on its own build it up
        if selected_duration <= min_duration:

            # Get the index of our selected file
            base_index = all_sorted_targets.index(selected_target)
            start_index = base_index
            end_index = base_index
            total_duration = selected_duration

            logging.info("Selected pcap (index: %s) is not large enough on its own (%s < %s). Preparing to merge target files.", base_index, selected_duration, min_duration)

            previous_end = selected_end
            for i in range(base_index + 1, len(all_sorted_targets)):
                current_pcap = all_sorted_targets[i]

                logging.debug("Checking duration of %s", current_pcap)
                target_data = get_target_metadata(current_pcap)
                if not target_data:
                    errors.append(("Bad Target Files", "Bad Duration", current_pcap))
                    bad_targets.append(current_pcap)
                    break

                current_duration = target_data[0]
                current_start = target_data[1]
                current_end = target_data[2]

                difference = (current_start - previous_end).total_seconds()

                if difference > 5:
                    logging.debug("More than 5 seconds between files. (Current Start: %s, Previous End: %s, Difference: %s", current_start, previous_end, difference)
                    break

                previous_end = current_end
                total_duration += current_duration

                # If we now have enough selected
                if total_duration > min_duration:
                    end_index = i
                    break

            logging.debug("Duration after forward check: %s", total_duration)
            # If we don't have enough files check in the other direction
            if total_duration <= min_duration:
                next_start = selected_start
                for i in range(base_index - 1, -1, -1):
                    current_pcap = all_sorted_targets[i]

                    logging.debug("Checking duration of %s", current_pcap)
                    target_data = get_target_metadata(current_pcap)
                    if not target_data:
                        errors.append(("Bad Target Files", "Bad Duration", current_pcap))
                        bad_targets.append(current_pcap)
                        break

                    current_duration = target_data[0]
                    current_start = target_data[1]
                    current_end = target_data[2]

                    difference = (next_start - current_end).total_seconds()

                    if difference > 5:
                        logging.debug("More than 5 seconds between files. (Current End: %s, Next Start: %s, Difference: %s", current_end, next_start, difference)
                        logging.debug("Resetting total duration to original selected duration.")
                        break

                    next_start = current_start
                    total_duration += current_duration

                    # If we now have enough selected
                    if total_duration > min_duration:
                        start_index = i
                        break

                logging.debug("Duration after backward check: %s", total_duration)

            if total_duration < min_duration:
                logging.info("Minimum duration not met. Trying again.")
                continue

            logging.info("Preparing to merge background traffic...")
            logging.info("Starting index: %s \t Ending index: %s", start_index, end_index)

            # Generate the filename
            try:
                # Get the filename without the extension to prevent filenames such as something.pcap-something2.pcap
                start_file_no_ext = os.path.splitext(os.path.basename(all_sorted_targets[start_index]))[0]
                end_file = os.path.basename(all_sorted_targets[end_index])
                filename = "{}_merged_{}-{}".format(mp.current_process().name, start_file_no_ext, end_file)
                merged_target_path = os.path.join(merged_target_dir, filename)

            except Exception as e:
                logging.error("Error building filename. Defaulting to use indexes rather than names. %s", str(e))
                filename = "{}_merged_{}-{}.pcap".format(mp.current_process().name, start_index, end_index)
                merged_target_path = os.path.join(merged_target_dir, filename)

            # Build and run our merge command
            try:
                file_format = 'pcap'
                if PCAP.tool_version < (1, 10, 2):
                    file_format = 'libpcap'

                logging.debug("Mergecap using '%s' as the file format", file_format)
                merge_cmd = ['mergecap', '-F', file_format, '-s', '68', '-w', merged_target_path]

                for i in range(start_index, end_index + 1):  # Note: the +1 is because range doesn't include the stop value
                    logging.debug("Appending file to merge list: %s", all_sorted_targets[i])
                    used_files.append(all_sorted_targets[i])
                    merge_cmd.append(all_sorted_targets[i])

                # Merge the necessary files
                PCAP.run_command(merge_cmd)
                target = merged_target_path

            except (AttributeError, ExternalToolError) as e:
                logging.error("Failed to Merge. Reason: %s", str(e))
                continue

        else:
            logging.info("Selected Target is sufficiently long by itself. ( %s > %s)", selected_duration, min_duration)
            target = selected_target
            used_files.append(selected_target)

        # We have a file that should be long enough, but lets double check and also put the pcap
        # in order if strict_time_order is not True.
        target_pcap = new_pcap(target)
        if not target_pcap:
            logging.error("Failed to instantiate %s", target)
            errors.append(("Bad Target Files", "Instantiation", target))
            bad_targets.append(target)
            continue

        # Ensure strict time order
        if not target_pcap.strict_time_order:
            try:
                # Get only the filename without the rest of the path or the extension.
                basename = os.path.splitext(os.path.basename(target_pcap.filepath))[0]
                re_ordered_filename = os.path.join(merged_target_dir, "{}_reordered_{}.pcap".format(basename, mp.current_process().name))

            except:
                re_ordered_filename = os.path.join(merged_target_dir, "reordered_{}.pcap".format(mp.current_process().name))

            # Re-order the pcap.
            target_pcap = re_order_pcap(target_pcap, re_ordered_filename)

            if not target_pcap:
                logging.error("Failed to load re-ordered pcap. Selecting new file...")
                continue

        # Check if it's a pcapng file and if so convert it to pcap.
        # TODO remove this once solution for handling pcapng has been found.
        if "pcapng" in target_pcap.file_type:
            try:
                logging.info("Converting %s from pcapng to pcap", target_pcap.filepath)
                basename = os.path.splitext(os.path.basename(target_pcap.filepath))[0]
                converted_filename = os.path.join(merged_target_dir, "{}_converted_{}.pcap".format(basename, mp.current_process().name))

            except:
                converted_filename = os.path.join(merged_target_dir, "converted_{}.pcap".format(mp.current_process().name))

            # Convert the file
            target_pcap.convert_to_pcap(converted_filename)
            target_pcap = new_pcap(converted_filename)

            if not target_pcap:
                logging.error("Failed to load converted pcap. Selecting new file...")
                continue

        # Double check duration
        if not ensure_data_longer_than_attack(attack_pcap, target_pcap, padding):
            logging.error("The selected target pcap was unexpectedly smaller than necessary (%s <= %s).",
                          target_pcap.capture_duration, min_duration)

        else:
            logging.debug("Target file sufficiently long. (%s > %s)", target_pcap.capture_duration, min_duration)
            return target_pcap, errors, used_files

    return None, errors, used_files


def mung(atk_pcap, tgt_pcap, output_file, victim_map, padding):
    """
    Perform the actual munging process.

    @param atk_pcap: The instance of the attack pcap to be used
    @type atk_pcap: PCAP
    @param tgt_pcap: The instance of the target pcap to be used
    @type tgt_pcap: PCAP
    @param output_file: The filename for the newly merged pcap
    @type output_file: str
    @param victim_map: Mapping of IP addresses from the attack network to the target network
    @type victim_map: dict
    @param padding: The amount of padding we want at the beginning and end of our new file.
    @type padding: float
    @return: The new PCAP as well as the new start and end times for the attack.
    @rtype: tuple
    """
    t1 = None
    t2 = None
    t3 = None

    try:
        output_dir = os.path.split(output_file)[0]

        # Calculate the necessary time shift and adjust time (editcap)
        try:
            # Set up temp files so that we can maintain the originals
            t1 = os.path.join(output_dir, '{}_shifted_attack'.format(mp.current_process().name))

            offset = calculate_needed_timeshift(atk_pcap, tgt_pcap, padding)
            atk_pcap.shift_time(t1, offset)
            shifted_attack = new_pcap(t1)

        except (RuntimeError, TypeError, ExternalToolError) as e:
            logging.error("Failed to shift attack pcap time for following reason: %s", str(e))
            logging.info("Unable to proceed with this attack file. See logs for more details.")
            return None, None, None

        else:
            logging.info("Shifted %s by an offset of %.6f and wrote to %s", atk_pcap.filepath, offset, t1)

        for count, original_victim_ip in enumerate(victim_map):
            # Set up temp files for this iteration of the swaps
            t2 = os.path.join(output_dir, "{}_swapped_ips_{}".format(mp.current_process().name, count))
            t3 = os.path.join(output_dir, "{}_swapped_macs_{}".format(mp.current_process().name, count))

            # Get mac address for the old victim. (tshark)
            try:
                logging.info("Determining MAC address for old victim(%s)...", original_victim_ip)
                old_victim_mac = atk_pcap.get_mac_for_ip(original_victim_ip)
                logging.info("%s MAC: %s", original_victim_ip, old_victim_mac)

            except Exception as e:
                logging.error("Failed to retrieve mac address for %s. Reason: %s", original_victim_ip, str(e))
                return None, None, None

            # Get mac address for the new victim (tshark)
            new_victim_ip = victim_map[original_victim_ip]
            try:
                logging.info("Determining MAC address for new victim(%s)...", new_victim_ip)
                new_victim_mac = tgt_pcap.get_mac_for_ip(new_victim_ip)
                logging.info("%s MAC: %s", new_victim_ip, new_victim_mac)

            except Exception as e:
                logging.error("Failed to retrieve mac address for %s. Reason: %s", new_victim_ip, str(e))
                return None, None, None

            # OK lets swap some info!
            # Change the IP of the victim in our shifted attack file (bittwiste)
            try:
                logging.info("Swapping victim IPs (%s -> %s)...", original_victim_ip, new_victim_ip)
                if count > 0:
                    logging.debug("IP Swap %s", count)
                    swapped_ips.swap_ips(t2, original_victim_ip, new_victim_ip)
                    swapped_ips = new_pcap(t2)
                else:
                    logging.debug("Original IP Swap")
                    shifted_attack.swap_ips(t2, original_victim_ip, new_victim_ip)
                    swapped_ips = new_pcap(t2)

            except Exception as e:
                logging.error("Failed to swap ips for the following reason: %s", str(e))
                return None, None, None

            # Change the MAC of the victim in the shifted, ip-swapped attack file
            try:
                logging.info("Swapping victim MACs (%s -> %s)...", old_victim_mac, new_victim_mac)

                if count > 0:
                    logging.debug("Mac Swap %s", count)
                    swapped_macs.swap_macs(t3, old_victim_mac, new_victim_mac)
                    swapped_macs = new_pcap(t3)
                else:
                    logging.debug("Original Mac Swap")
                    swapped_ips.swap_macs(t3, old_victim_mac, new_victim_mac)
                    swapped_macs = new_pcap(t3)

            except Exception as e:
                logging.error("Failed to swap MACs for the following reason: %s", str(e))
                return None, None, None

        # Let's Munge!
        try:
            logging.info("Merging the modified attack data with the target data...")
            tgt_pcap.merge_pcaps(swapped_macs, output_file)

        except ExternalToolError as e:
            logging.error("Failed to merge for the following reason: %s", str(e))
            return None, None, None

        else:
            logging.info("Merge successful.")

        # Let's make sure we can load our newly created pcap
        return new_pcap(output_file), shifted_attack.start_time, shifted_attack.end_time

    except Exception as e:
        logging.error("The following unhandled error occured: %s", str(e))

    finally:
        # Ensure that temp files get deleted no matter if an exception was raised.
        temp_files = glob.glob(os.path.join(output_dir, '{}*'.format(mp.current_process().name)))
        for temp in temp_files:
            try:
                os.remove(temp)
            except OSError:
                pass


def merge_xmls(dir_path):
    munged_attack_dir = os.path.join(dir_path, "Attack")
    folder_name = os.path.basename(munged_attack_dir)

    try:
        # Delete Attack directory if no files are contained within it.
        if not os.listdir(munged_attack_dir):
            try:
                logging.warning("No files found in %s. Preparing to remove directory", folder_name)
                os.rmdir(munged_attack_dir)
            except:
                logging.error("Failed to remove %s.", munged_attack_dir)

            return

        # Setup our new xml file
        metadata_filename = "{}_metadata.xml".format(folder_name)
        metadata_file = os.path.join(munged_attack_dir, metadata_filename)

        # Get all the xml files
        glob_str = os.path.join(munged_attack_dir, "*.xml")
        xmls = glob.glob(glob_str)

        # If there are no xmls move on
        if not xmls:
            raise RuntimeError("No xmls found in {}".format(folder_name))

        # Make the root node
        pcap_data = Element("pcapData")

        # Iterate through all the xmls
        for xml in xmls:
            tree = parse(xml)
            root = tree.getroot()

            for pcap_node in root.findall("pcap"):
                pcap_data.append(pcap_node)

        merged = ElementTree(pcap_data)
        merged.write(metadata_file)

        # Once we've done the merge lets get rid of the old ones
        for xml in xmls:
            # Check to make sure it's not the merged xml before removing.
            # If this is a resume munge, then the original Attack_metadata.xml will be in this list
            # which would cause it to get removed along with the individual xml's.
            if os.path.basename(xml).startswith("Attack"):
                continue

            os.remove(xml)

    except Exception as e:
        logging.error("Unexpected error occurred merging the xmls for %s. %s", folder_name, str(e))

    return


def write_metadata_file(file_path, dest_ip, source_ip, label):
    """
    Outputs the requisite metadata to a file

    @param file_path: Destination location for the metadata file
    @type file_path: str
    @param dest_ip: The ip representing our victim
    @type dest_ip: str
    @param source_ip: The ip representing our attacker
    @type source_ip: str
    @param label: What type of attack the associated pcap represents.
    @type label: str
    @return: None
    @rtype: None
    """
    xml_file = "{}_metadata.xml".format(file_path)
    with open(xml_file, 'w') as f:
        f.write("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n")
        f.write("  <pcapData>\n")
        f.write("    <pcap file=\"{}\">\n".format(os.path.basename(file_path)))
        f.write("    <filters>\n")
        f.write("      <label value=\"{}\" />\n".format(label))
        f.write("      <filter sourceIP=\"{}\" destIP=\"{}\" />\n".format(source_ip, dest_ip))
        f.write("    </filters>\n")
        f.write("  </pcap>\n")
        f.write("</pcapData>\n")


def write_updated_metadata_file(old_xml, new_pcap_inst, victim_map, atk_start, atk_end):
    """
    This method combines the data from the inserted attack pcap's xml file with data from our newly merged pcap in
    order to create a new xml with updated information to reflect the changes caused by the merge

    @param old_xml: The xml file for the original attack pcap
    @type old_xml: str
    @param new_pcap_inst: The instance of the pcap we are making the new xml for
    @type new_pcap_inst: PCAP
    @param victim_map: mapping of the original victim IPs to the new victim IPs
    @type victim_map: dict
    @param atk_start: new start time of the attack
    @type atk_start: float
    @param atk_end: new end time of the attack
    @type atk_end: float
    @return: True or False to indicate success
    @rtype: bool
    """
    try:
        # Check if the xml actually exists
        if not os.path.isfile(old_xml):
            logging.error("XML file does not exist: %s", old_xml)
            return False

        else:
            tree = parse(old_xml)
            root = tree.getroot()

            # We need to update the filename in our new xml
            pcap_inst = root.findall(".//pcap[@file]")
            if not pcap_inst:
                logging.error("No pcap file was specified in the following xml: %s", old_xml)
                return False

            # Not sure if this is possible but including just to be safe
            elif len(pcap_inst) > 1:
                logging.error("Multiple file names were found. Unsure how to proceed")
                return False

            else:
                pcap_file = pcap_inst[0]
                pcap_file.set("file", os.path.basename(new_pcap_inst.filepath))

            for old_victim in victim_map:
                # Get the filter with our info
                filters = root.findall(".//filter[@destIP='{}']".format(old_victim))

                if not filters:
                    logging.error("No filters were found in the xml file with a destIP of %s", old_victim)

                for xml_filter in filters:
                    xml_filter.set("destIP", victim_map[old_victim])
                    xml_filter.set("endTime", "{:.6f}".format(atk_end))
                    xml_filter.set("startTime", "{:.6f}".format(atk_start))

            # Write out our new metadatafile
            metadata_file = "{}_metadata.xml".format(new_pcap_inst.filepath)
            tree.write(metadata_file)

            return True

    except Exception as e:
        logging.error(str(e))
        logging.error("Failed to write updated metadata file for %s", new_pcap_inst.filepath)
        return


def verify_results(attack_pcap, target_pcap, result_pcap):
    """
    Verify that the files successfully merged.

    @param attack_pcap: PCAP instance representing the attack file
    @type attack_pcap: PCAP
    @param target_pcap: PCAP instance representing the target file
    @type target_pcap: PCAP
    @param result_pcap: PCAP instance representing the file that resulted from merging the attack and target files
    @type result_pcap: PCAP
    @return: Whether the merge was successful or not
    @rtype: bool
    """
    all_good = True

    # - num of pkts in result should be target + attack
    actual = result_pcap.packet_count
    expected = attack_pcap.packet_count + target_pcap.packet_count

    if actual == expected:
        logging.debug("Verification: Packet Counts Match!!!")
    else:
        all_good = False
        logging.error("Packet Count Verification Failed! %s != %s", str(actual), str(expected))
        logging.info("Attack Packet Ct: %s", str(attack_pcap.packet_count))
        logging.info("Target Packet Ct: %s", str(target_pcap.packet_count))
        logging.info("Result Packet Ct: %s", str(actual))

    # - start time of output should == start time of target file
    if result_pcap.start_time == target_pcap.start_time:
        logging.debug("Verification: Start Times Match!!!")
    else:
        all_good = False
        logging.error("Start Time Verification Failed! Result capture start time does not equal target "
                      "capture start time")
        logging.info("Result Start Time: %s", PCAP.get_time_as_string(result_pcap.start_time))
        logging.info("Target Start Time: %s", PCAP.get_time_as_string(target_pcap.start_time))

    # - duration of output should == duration of target.
    actual = result_pcap.capture_duration
    expected = target_pcap.capture_duration

    if actual == expected:
        logging.debug("Verification: Duration Matches!!!")
    else:
        all_good = False
        logging.error("Capture Duration Verification Failed! Result capture duration does not equal target duration.")
        logging.info("Result Duration: %s", str(actual))
        logging.info("Target Duration: %s", str(expected))

    if all_good:
        logging.info("Verification Successful!!!")
    else:
        logging.info("Verification Failed!!!")

    return all_good


def process_attack(conf_values, sorted_targets, bad_target_list, logging_queue, logging_configurer, file_tuple):
    # setup Logging for multiprocessing
    logging_configurer(logging_queue)

    errors = []
    attack_file = file_tuple[0]
    target_list = file_tuple[1]

    # Get the basename of our attack file
    atk_basename = os.path.basename(attack_file)
    atk_name = os.path.splitext(atk_basename)[0]

    logging.info("Processing Attack File: %s", atk_basename)

    try:
        # set up key pieces into local variables
        output_dir = conf_values["OutputPath"]
        merged_target_dir = conf_values["MergedTargetPath"]
        networks = conf_values["Networks"]
        padding = conf_values["Padding"]

        # Check if we already have a munge(s) for this example
        existing_mung = existing_mung_check(output_dir, atk_name)

        # if there is already at least 1 munge with the same basename we can skip this attack file.
        if existing_mung:
            logging.info("Munging has already been performed for %s.", atk_basename)
            return [("Existing Munge", atk_basename)]

        # get data for attack file
        attack_pcap = new_pcap(attack_file)

        if attack_pcap is None:
            logging.error("Error creating PCAP instance for %s. Skipping attack file", atk_basename)
            return [("Skipped Attack Files", "Instantiation", atk_basename)]

        # Get the previous attack information. If can't get it drop this file
        try:
            xml_file = "{}.xml".format(os.path.splitext(attack_file)[0])
            attack_info = get_attack_info(xml_file)

        except (FileNotFoundError, AttributeError, ParseError) as err:
            logging.error("Unable to obtain attack information for %s. %s", atk_basename, str(err))
            return [("Skipped Attack Files", "Bad/Missing XML", atk_basename)]

        # Setup the munged attack directory for this label
        munged_atk_dir = os.path.join(output_dir, "Attack")
        try:
            os.makedirs(munged_atk_dir, exist_ok=True)

        except OSError as e:
            logging.error("Unexpected error setting up the munged attack directory: %s", e.strerror)
            return [("Skipped Attack Files", "Bad Destination", atk_basename)]

        # Ensure that it is in order. If not order it
        if not attack_pcap.strict_time_order:
            try:
                # Get only the filename without the rest of the path or the extension.
                re_ordered_filename = os.path.join(merged_target_dir, "{}_reordered_{}.pcap".format(atk_name, mp.current_process().name))

            except:
                re_ordered_filename = os.path.join(merged_target_dir, "reordered_{}.pcap".format(mp.current_process().name))

            # Re-order the pcap.
            attack_pcap = re_order_pcap(attack_pcap, re_ordered_filename)

            if not attack_pcap:
                logging.error("Failed to load re-ordered pcap. Skipping the following attack file: %s", atk_basename)
                return [("Skipped Attack Files", "Re Ordering Error", atk_basename)]

        # setup for selecting victims for the attack.
        used_victim_ips = []

        # Get the old Victim info- we assume destIP is victim
        original_vics = {vic["destIP"] for vic in attack_info}

        # For each attack file we want to perform the specified number of merges
        iterations = len(target_list)
        for i, target_file in enumerate(target_list):
            try:
                logging.info("Iteration %d of %d for current attack file.", i + 1,  iterations)
                # Now lets see if the target we selected will work. If not select a new target.

                # Select a background file.
                target_pcap, error_list, target_list = check_target(attack_pcap, target_file, sorted_targets,
                                                                    bad_target_list, merged_target_dir, networks, padding)

                if target_pcap is None:
                    logging.error("No suitable target file was found. Skipping the following attack file: %s", atk_basename)
                    errors.append(("Skipped Attack Files", "No Target", atk_basename))
                    break

                # Add errors to error list
                errors.extend(error_list)  # Verify that this is doing what it should

                logging.info("Selected Data File: %s", target_pcap.filepath)

                # Select new victim ips based on valid ip range & that hasn't been used previously for this attack
                victim_mapping = get_new_victims(original_vics, target_pcap, networks, used_victim_ips)
                logging.info("Selected Victim IPs: %s", json.dumps(victim_mapping))

                if not victim_mapping:
                    logging.error("Failed to select new victims. Skipping this iteration of the attack file.")
                    errors.append(("Bad Target Files", "No Valid Ips", target_pcap.filepath))
                    continue

                # build the path for our newly merged file.
                out_filename = "{}_Merge{:02d}.pcap".format(atk_name, i + 1)
                out_filepath = os.path.join(munged_atk_dir, out_filename)

                # Perform Munging
                munged_pcap, atk_start, atk_end = mung(attack_pcap, target_pcap, out_filepath, victim_mapping,
                                                       padding)

                if munged_pcap is None:
                    logging.critical("An error occurred in the munging process. Skipping this iteration of the attack file")
                    # TODO this needs to be made more specific.
                    errors.append(("Munging Failures", "Munging Error", atk_basename, target_pcap.filepath))
                    continue

                # Verify that changes were successful
                results_ok = verify_results(attack_pcap, target_pcap, munged_pcap)
                if not results_ok:
                    logging.error("Results were not valid. Not writing metadata file and removing merged file.")
                    errors.append(("Munging Failures", "Verification Failed", atk_basename, target_pcap.filepath))

                    # Remove the merged file if it failed.
                    os.remove(munged_pcap.filepath)

                else:
                    # Output Metadata
                    logging.info("Writing updated metadata to %s", out_filepath)
                    write_updated_metadata_file(xml_file, munged_pcap, victim_mapping, atk_start, atk_end)

            except Exception as e:
                logging.exception("An unexpected error occured processing this iteration of the attack file.")

            finally:
                # Remove the target file if it is one we created (ie merged) to stop unnecessary storage problem.
                if target_pcap:
                    try:
                        if os.path.basename(target_pcap.filepath).startswith('PoolWorker-'):
                            os.remove(target_pcap.filepath)
                    except:
                        # Don't need to worry to much about it. The file will be deleted at the end.
                        logging.error("Failed to remove %s", target_pcap.filepath)

    except KeyError as e:
        logging.critical("Unable to start auto run do to missing configuration key: %s", str(e))

    except:
        logging.exception("An unexpected error occurred while processing %s. Skipping remaining iterations", atk_basename)

    return errors


def write_error_data(error_collection, log_dir, total_attacks, total_targets):
    # Setup our error dictionary
    error_dict = {
        "Skipped Attack Files": {
            "Instantiation": [],
            "Bad/Missing XML": [],
            "No Target": [],
            "Re Ordering Error": [],
            "Bad Destination": []
        },
        "Munging Failures": {
            "Bad Target": [],
            "Munging Error": [],
            "Verification Failed": []
        },
        "Bad Target Files": {
            "Bad Duration": [],
            "No Valid Ips": [],
            "Instantiation": []
        }
    }

    # Set variables for statistics
    skipped_attack_files = 0
    bad_target_files = 0
    num_munging_errors = 0
    existing_munge_count = 0

    for error_list in error_collection:

        for error in error_list:
            category = error[0]

            # If it's an attack or target file error we only get the name of the pcap
            # i.e. ("Skipped Attack Files", "No Target", somefile.pcap)
            # Get counts
            if category == "Skipped Attack Files":
                skipped_attack_files += 1
                error_dict[category][error[1]].append(error[2])

            elif category == "Bad Target Files":
                bad_target_files += 1
                error_dict[category][error[1]].append(error[2])

            # Its a munging error so we get both the attack and target files
            # i.e ("Munging Failures", "Munging Error", some_attack.pcap, some_target.pcap)
            elif category == "Munging Failures":
                num_munging_errors += 1
                error_dict[category][error[1]].append({"Attack": error[2], "Target": error[3]})

            elif category == "Existing Munge":
                existing_munge_count += 1

            else:
                logging.error("Unexpected category: %s", category)

    # Print the categorizations in the log file.
    logging.info("Categorization of Attack File Errors: ")
    for i, item in enumerate(error_dict["Skipped Attack Files"]):
        pos = i + 1
        logging.info("%d. %s: %d", pos, item, len(error_dict["Skipped Attack Files"][item]))

    logging.info("Categorization of Target File Errors: ")
    for i, item in enumerate(error_dict["Bad Target Files"]):
        pos = i + 1
        logging.info("%d. %s: %d", pos, item, len(error_dict["Bad Target Files"][item]))

    logging.info("Number of Attack Files skipped due to existing munges: %d / %d", existing_munge_count, total_attacks)
    logging.info("Number of Attack Files skipped completely due to an error: %d / %d", skipped_attack_files, total_attacks)
    logging.info("Number of bad Target Files : %d / %d", bad_target_files, total_targets)
    logging.info("Number of individual munging errors: %d", num_munging_errors)

    failed_data_path = os.path.join(log_dir, "failed_files.json")
    with open(failed_data_path, 'w') as outfile:
        outfile.write(json.dumps(error_dict, indent=3))


def auto_run(conf_values, run_type):
    """
    Run the munging program over all attack files in a given directory using background files
    from another provided directory.

    @param conf_values: All the configuration values that were provided by the config file
    @type conf_values: dict
    @param run_type: If this is a training or validation run
    @type run_type: str

    """
    # Setup our Multiprocessing Manager to handle sharing a list of bad files
    m = Manager()
    bad_targets = m.list([])
    q = m.Queue()  # Set up our logging Queue

    # Set up our logging listener
    listener = mp.Process(target=listener_process, args=(q, listener_configurer, conf_values))
    listener.start()

    process_configurer(q)

    # Lets see if our config file has the necessary information
    valid_args = check_args(conf_values, run_type)

    if not valid_args:
        logging.critical("One or more configuration options were invalid. See log for more details")
        raise RuntimeError

    # First check that all the necessary tools are present
    logging.debug("Checking if required tools are present")
    tools_ok = PCAP.verify_tools()
    if not tools_ok:
        raise ExternalToolError('Not all required tools were found. Please install the missing tools and try again')

    # set up key pieces into local variables
    attack_dir = conf_values["RawTrainingSamples"] if run_type == "training" else conf_values["RawValidationSamples"]
    target_dir = conf_values["SelectedNormalSamples"]
    log_dir = conf_values["LogDir"]

    try:

        logging.info("Starting PCAP Munger")
        found_files = True

        # Get all pcaps in the attack and target directories
        attack_files = get_pcaps_from_dir(attack_dir, conf_values["Source"], conf_values["Type"])
        target_files = get_pcaps_from_dir(target_dir)

        # Get some basic stats to display
        num_atk = len(attack_files)
        num_tar = len(target_files)
        logging.info("Found %d attack files in %s", num_atk, attack_dir)
        logging.info("Found %d target files in %s", num_tar, target_dir)

        if not attack_files:
            logging.error("No attack pcaps were found in %s with a source of %s and type of %s", attack_dir,
                          conf_values["Source"], conf_values["Type"])
            found_files = False

        if not target_files:
            logging.error("No target pcaps were found in %s", target_dir)
            found_files = False

        if not found_files:
            logging.critical("Problem gathering attack and target pcaps. Exiting")
            return

        # map each attack to a set of target files equal to the number of merges per attack.
        task_list = []
        mapping_targets = []

        SystemRandom().shuffle(target_files)
        while len(mapping_targets) < (len(attack_files) * conf_values['NumMergesPerAttack']):
            mapping_targets.extend(target_files)

        for attack_file in attack_files:
            attack_targets = [mapping_targets.pop() for i in range(conf_values['NumMergesPerAttack'])]

            task_list.append((attack_file, attack_targets))

        # Setup our pool with either the # of threads specified in the properties file or the # of cpu's -1
        try:
            num_processes = conf_values["NumMungerThreads"]
            logging.info("Utilizing %s processes.", num_processes)

        except (KeyError, ValueError):
            cpu_count = mp.cpu_count()
            num_processes = cpu_count - 1 if cpu_count > 2 else cpu_count
            logging.info("Error getting the number of processes from config file. Defaulting to %s", num_processes)

        pool = Pool(num_processes)

        try:
            func_partial = partial(process_attack, conf_values, sorted(target_files), bad_targets, q, process_configurer)
            error_data = pool.map_async(func_partial, task_list).get(9999999)  # https://stackoverflow.com/a/1408476
            # TODO can we monitor the result list to get our current position?
            pool.close()
            pool.join()

            write_error_data(error_data, log_dir, num_atk, num_tar)

            # Merge new XML's into one large XML
            logging.info("Merging XML files")
            merge_xmls(conf_values["OutputPath"])

            logging.info("Munging Complete")

        except KeyboardInterrupt:
            logging.info('KeyboardInterrupt detected. Stopping all processes')

        except:
            traceback.print_exc()

    except:
        traceback.print_exc()
        raise

    finally:
        # Remove the merged file directory
        try:
            logging.debug("Removing merged file directory...")
            shutil.rmtree(conf_values["MergedTargetPath"])

        except Exception as e:
            logging.error("Error removing merged file directory %s. %s", conf_values["MergedTargetPath"], str(e))

        q.put_nowait(None)
        listener.join()


def main():

    # Set up the parser to accept one argument for the config file
    parser = ModifiedParser()
    parser.add_argument("configFile", help="Path to the configuration file")

    run_type = parser.add_mutually_exclusive_group(required=True)
    run_type.add_argument('-t', '--training', action='store_true', help='Munging should be performed on the training data')
    run_type.add_argument('-v', '--validation', action='store_true', help='Munging should be performed on the validation data')

    # Parse the arguments
    args = parser.parse_args()
    run_type_value = "training" if args.training else "validation"

    logging.info("Attack PCAP Munger")

    # Get the configuration file
    try:
        with open(args.configFile) as f:
            config = json.load(f)

    except IOError as e:
        logging.critical("Failed to load configuration file for the following reason: %s", str(e.strerror))
        raise

    except ValueError as e:
        logging.critical("Invalid configuration file. %s", str(e))
        raise

    # check if config contains info for the munger
    try:
        munger_props = config["PcapMunger"]
    except KeyError:
        logging.critical("No properties found for the PcapMunger. Unable to continue.")
        raise

    auto_run(munger_props, run_type_value)


if __name__ == "__main__":
    try:
        startTime = datetime.now()
        main()
        logging.info("Script took %s to complete", format(datetime.now()-startTime))
    except:
        sys.exit(1)
    finally:
        logging.shutdown()
