$ sudo apt-get update && sudo apt-get upgrade
$ sudo apt-get install virtualenv python3 python3-dev python-dev gcc libpq-dev libssl-dev libffi-dev build-essentials
$ virtualenv -p /usr/bin/python3 .env
$ source .env/bin/activate
$ pip install -r requirements.txt


Before running the software, add the API Keys Phishtank in the config.ini file.

Now, run:

$ python run.py <input-url-file> <output-dataset>

Author : Inzamamul Alam Munna