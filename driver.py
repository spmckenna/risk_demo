import sys
import subprocess
import os
from streamlit import cli as stcli

# if __name__ == '__main__':
#    sys.argv = ["streamlit", "run", "app.py"]
#    sys.exit(stcli.main())


process = subprocess.Popen(["streamlit", "run", os.path.join('application', 'main', 'services', 'app.py')], shell=True,
                           stdin=None,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           close_fds=True)
out, err = process.communicate()
