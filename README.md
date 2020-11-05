# auto_provision A script to auto provision the devices in cisco dnac

in cisco dnac, when devices are added to non-fabric site. devices needs to be claimed manually and added/provisioned to the site.
this script will automate the process of claim & provision.
script was written to interactively get the input from users.

packages required to run the script

import json
import requests
import base64

script can be run inside the dnac cli. or any python environment where above packages are installed.
