#!/usr/bin/python
# vim: expandtab:tabstop=4:shiftwidth=4
'''
    Tool to provide developers with ability to remotely run a limited
    set of commands.
'''
# Disabling invalid-name because pylint doesn't like the naming conention we have.
# pylint: disable=invalid-name

import logging
import os
import re
import subprocess
import sys

class WhitelistedCommands(object):
    ''' Class to hold functions implementing allowed functionality '''
    KUBECONFIG = '/home/jdiaz/kubeconfig'

    def __init__(self, kubeconfig_path=None):
        if kubeconfig_path is not None:
            WhitelistedCommands.KUBECONFIG = kubeconfig_path

    @staticmethod
    def tail_var_log_messages(cmd):
        print "CMD: {} CMD".format(cmd)
        my_cmd = "/usr/bin/sudo /usr/bin/tail -f /var/log/messages".split()
        os.execv('/usr/bin/sudo', my_cmd)
        
class SudoCommands(object):
    ''' Class to wrap approved developer access commands '''
    def __init__(self):
        self._args = None

        self.parse_args()
        self.setup_logging()
        logging.debug("Got args: " + str(self._args))

        self._command_dict = self.whitelisted_command_list()

    @staticmethod
    def whitelisted_command_list():
        ''' Dict with key of whitelisted commmands mapped to their 
            actual implementation.
            The commands should be in 'normalized' output style from OCCmd.
        '''
        command_dict = {}

        ### original example commands
        command_dict['tail -f /var/log/messages'] = WhitelistedCommands.tail_var_log_messages

        return command_dict

    def parse_args(self):
        ''' read in argv minus the very first parameter '''

        args = " ".join(sys.argv[1:])

        self._args = args

    def setup_logging(self):
        ''' Configure logging '''
        LOGFILE = "/home/jdiaz/devget.log"

        # Default log level
        if os.environ.has_key("DEVGET_DEBUG"):
            log_level = logging.DEBUG
        else:
            log_level = logging.INFO

        logging.basicConfig(filename=LOGFILE, format="%(asctime)s %(message)s",
                            level=log_level)
        #if self._args.verbose:
        #    # Print to stdout in addition to log file
        #    logging.getLogger().addHandler(logging.StreamHandler())

    def main(self):
        ''' Entry point for class '''
        cmd = self._args
        logging.info("sudo command: {}".format(self._args))

        if self._command_dict.has_key(cmd):
            results = self._command_dict[cmd](cmd)
            print results
        else:
            raise Exception("Unallowed command: {}".format(cmd))
 

if __name__ == '__main__':
    scmds = SudoCommands()
    scmds.main()
