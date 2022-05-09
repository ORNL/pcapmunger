Python PCAP Munger
============

Project for overlaying attacks onto existing PCAP data. The included scripts were originally a part of the training pipeline for the Oak Ridge Cyber Analytics (ORCA) project and have been distributed now under an open source license to facilitate the publication of PCAP datasets.

The included script can be used to munge malicious attack examples with that of a target network's background traffic.


## External dependancies ##
The following tools and their dependancies need to be installed in order for the program to work. All tools
need to be accessible by your Path.

+ Wireshark - Download at <http://www.wireshark.org>. *Needs to be at least version 1.8.0. Due to changes in capinfos,
version 2.0.0 or above is recomended.*
+ Bittwist/Bittwiste - Download at <http://bittwist.sourceforge.net/>
+ TCPDUMP or WinDump - If you are running Mac or Linux TCPDUMP is required. If you're running Windows, you need WinDump.
 Download at <http://www.tcpdump.org/> and <http://www.winpcap.org/windump/> respectively.


## Usage ##
The main entry point of this project is through pcapmunger.py. See the following usage example for how to run it.

	usage: pcapmunger.py [-h] configFile

	positional arguments:
	  configFile  Path to the configuration file

	optional arguments:
	  -h, --help  show this help message and exit

Additional configuration options can be set in the 'pcapmunger-properties.json' file

## Example ##
A sample dataset is included in the 'Attack_Samples' and 'Background_Traffic_Samples' folders.

Run the example by executing the following command:
```bash
python pcapmunger.py -p pcapmunger-properites.json
```
The samples will be munged and the resulting pcaps will be written to the 'MungedTrainingSamples' folder.
