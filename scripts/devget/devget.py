#!/usr/bin/python
# vim: expandtab:tabstop=4:shiftwidth=4
'''
    Tool to provide developers with ability to remotely run a limited
    set of commands.
'''
# Disabling invalid-name because pylint doesn't like the naming conention we have.
# pylint: disable=invalid-name

import ConfigParser
import json
import logging
import os
import re
import subprocess
import sys
import yaml

class OCCmd(object):
    ''' Class to hold and standardize building of /usr/bin/oc commands
        out of raw bash command line text '''
    def __init__(self, raw_cmd):
        # original command line text
        self._raw_cmd = raw_cmd
       
        # always define a namespace
        self._namespace = 'default'
        # whether special output formatting is requested
        self._output_format = None
        # --follow or -f
        self._follow = None
        # -c for 'oc get logs -c <container>
        self._container = None

        # the actual command to run (ie oc get pods or oc get secrets my-secret)
        self._verb = None
        self._type = None
        self._subject = None
        self.parse_cmd()

    def get_namespace(self, cmd):
        ''' find a namespace (if passed in) and return cmd
            without the namespace-related parameters '''

        cmd_split = cmd.split()
        delete_tokens = []

        for x in range(0, len(cmd_split)):
            if cmd_split[x] == '-n':
                # token was exactly '-n' so next token is the namespace
                self._namespace = cmd_split[x+1]

                # make sure to mark these items for removal from list
                # before returning the command
                delete_tokens.append(cmd_split[x])
                delete_tokens.append(cmd_split[x+1])

                # skip next token since we already processed it
                x = x + 1
            elif cmd_split[x].startswith('-n'):
                # we have a namespace in the format of -n<namespace>
                self._namespace = re.sub('-n', '', cmd_split[x])

                delete_tokens.append(cmd_split[x])
            # elif match --namespace and --namespace=<namespace> params

        # now clean up namespace-related tokens before returning
        # cmd without the namespace-related parameters
        for token in delete_tokens:
            cmd_split.remove(token)

        new_cmd = " ".join(cmd_split)
        return new_cmd
         
    def get_follow(self, cmd):
        ''' find -f --follow (if passed in) and return cmd without
            the param '''

        cmd_split = cmd.split()
        delete_tokens = []

        for x in range(0, len(cmd_split)):
            if cmd_split[x] == '-f' or cmd_split[x] == '--follow':
                self._follow = '--follow'
                delete_tokens.append(cmd_split[x])

        for token in delete_tokens:
            cmd_split.remove(token)

        new_cmd = " ".join(cmd_split)
        return new_cmd

    def get_output_format(self, cmd):
        ''' find output format parameters (if passed in) and return cmd
            without the format parameters '''

        cmd_split = cmd.split()
        delete_tokens = []

        for x in range(0, len(cmd_split)):
            if cmd_split[x] == '-o':
            # token was exactly '-o' so next token is output format
                self._output_format = cmd_split[x+1]

                # mark tokens for removal
                delete_tokens.append(cmd_split[x])
                delete_tokens.append(cmd_split[x+1])

                # skip next token since we already processed it
                x = x + 1
            elif cmd_split[x].startswith('-o'):
                # we have an output in format -o<output_format>
                self._output_format = re.sub('-o', '', cmd_split[x])

                delete_tokens.append(cmd_split[x])

        # clean up output-related tokens and return resulting string
        for token in delete_tokens:
            cmd_split.remove(token)

        new_cmd = " ".join(cmd_split)
        return new_cmd

    def get_container(self, cmd):
        ''' Take '-c' command line param (for oc logs)
            Return remaining string '''
        cmd_split = cmd.split()
        delete_tokens = []

        for x in range(0, len(cmd_split)):
            if cmd_split[x] == '-c':
                self._container = cmd_split[x+1]

                # mark tokens for removal
                delete_tokens.append(cmd_split[x])
                delete_tokens.append(cmd_split[x+1])

                # skip next token since we already processed it
                x = x + 1
            elif cmd_split[x].startswith('-c'):
                self._container = re.sub('-c', '', cmd_split[x])

                delete_tokens.append(cmd_split[x])

        for token in delete_tokens:
            cmd_split.remove(token)

        new_cmd = " ".join(cmd_split)
        return new_cmd

        
    def get_verb_type_subject(self, cmd):
        ''' Take command without parameters and parse it into its
            various components.
            Return remaining string (should be "")
        '''
        cmd_split = cmd.split()

        # handle 'oc <verb> <type> <optional-subject>' type of cmd
        cmd_split.remove("oc")

        # make sure none of the remaining tokens are parameters
        for param in cmd_split:
            if param.startswith('-'):
                raise Exception('Should not have any more parameters left for processing')

        self._verb = cmd_split[0]
        self._type = cmd_split[1]
        if len(cmd_split) > 2:
            self._subject = cmd_split[2]

        if self._verb == 'logs':
            # logs commands aren't in the form of verb type subject
            # just verb subject, so wipe out _type and store it in 
            # _subject instead
            self._subject = self._type
            self._type = None

        cmd_split.remove(self._verb)
        if self._type is not None:
            cmd_split.remove(self._type)
        if self._subject is not None:
            cmd_split.remove(self._subject)

        return " ".join(cmd_split)

    def parse_cmd(self):
        ''' take a raw oc command and tokenize it '''

        #
        # Get all params first
        #
        cmd_no_namespace = self.get_namespace(self._raw_cmd)

        cmd_no_output_formatting = self.get_output_format(cmd_no_namespace)

        cmd_no_follow = self.get_follow(cmd_no_output_formatting)

        cmd_no_container = self.get_container(cmd_no_follow)

        #
        # all that is left should be: 'oc <verb> <type> <optional-subject>'
        #
        cmd = self.get_verb_type_subject(cmd_no_container)


        # should be nothing left after we parsed all the tokens
        if cmd != "":
            raise Exception("Unprocessed command tokens left.")

    def normalized_cmd(self, generic=False):
        ''' return 'normalized' string in the format:
            oc <action> <type> <opt-subject> -n<namespace> -o<output_format> --follow
            Use generic=True to substitue out thing with subject-specific parameters
            (ie. router-3-abx3j changed to SUBJECT) for easier command matching
        '''
        normalized_cmd = "oc"

        for item in [self._verb, self._type]:
            if item is not None:
                normalized_cmd = "{orig} {token}".format(orig=normalized_cmd,
                                                         token=item)

        if self._subject is not None:
            if generic:
                normalized_cmd = "{orig} SUBJECT".format(orig=normalized_cmd)
            else: 
                normalized_cmd = "{orig} {subject}".format(orig=normalized_cmd,
                                                           subject=self._subject)

        if self._container is not None:
            # add container
            if generic:
                normalized_cmd = "{orig} -cSUBJECT".format(orig=normalized_cmd)
            else:
                normalized_cmd = "{orig} -c{container}".format(orig=normalized_cmd,
                                                               container=self._container)
        # add namespace
        normalized_cmd = "{orig} -n{namespace}".format(orig=normalized_cmd,
                                                       namespace=self._namespace)
        # add output formatting
        if self._output_format is not None:
            normalized_cmd = "{cmd} -o{oformat}".format(cmd=normalized_cmd,
                                                        oformat=self._output_format)

        # add --follow
        if self._follow is not None:
            normalized_cmd = "{cmd} {follow}".format(cmd=normalized_cmd,
                                                     follow=self._follow)

        return normalized_cmd


class WhitelistedCommands(object):
    ''' Class to hold functions implementing allowed functionality '''
    KUBECONFIG = '/home/jdiaz/kubeconfig'

    def __init__(self, kubeconfig_path=None):
        if kubeconfig_path is not None:
            WhitelistedCommands.KUBECONFIG = kubeconfig_path

    @staticmethod
    def redact_env_values(dict_list, env_names):
        for item in dict_list:
            if item['name'] in env_names:
                item['value'] = 'REDACTED'

    @staticmethod
    def redact_pod_env_values(pod, env_names):
        ''' Search through provided list of dicts for env_names
            and set 'value' to 'REDACTED' on all matched dict entries.
            This does an in-place modification and doesn't return
            the resulting modified object.
        '''
        if pod['spec']['containers'][0].has_key('env'):
            for item in pod['spec']['containers'][0]['env']:
                if item['name'] in env_names:
                    item['value'] = 'REDACTED'

    @staticmethod
    def redact_items(output, redact_list, output_format):
        yaml_results = yaml.load(output)
        pod_list = []
        if yaml_results.has_key('items'):
            pod_list.extend(yaml_results['items'])
        else:
            pod_list.append(yaml_results)

        for pod in pod_list:
            WhitelistedCommands.redact_pod_env_values(pod, redact_list)

        if output_format == 'yaml':
            results = yaml.dump(yaml_results, default_flow_style=False)
        elif output_format == 'json':
            results = json.dumps(yaml_results, sort_keys=True,
                                 indent=4)

        return results

    @staticmethod
    def oc_cmd_builder(cmd):
        ''' Add default command-line args for 'oc' commands '''
        cmd_to_run = cmd.split()
        cmd_to_run.extend(['--config', WhitelistedCommands.KUBECONFIG])
        return cmd_to_run
        
    @staticmethod
    def oc_get_pods(occmd):
        ''' oc get pods '''
        redact_env_vars = ['STATS_PASSWORD', 'OPENSHIFT_KEY_DATA',
                           'REGISTRY_HTTP_SECRET']

        normalized_cmd = occmd.normalized_cmd()
        cmd_to_run = WhitelistedCommands.oc_cmd_builder(normalized_cmd)
        results = subprocess.check_output(cmd_to_run)

        # redact with -oyaml -ojson output
        if occmd._output_format is not None:
            results = WhitelistedCommands.redact_items(results,
                                                        redact_env_vars,
                                                        occmd._output_format)
            
        return results

    @staticmethod
    def oc_get_logs(occmd):
        ''' oc get logs SUBJECT <--follow> '''

        norm_cmd = occmd.normalized_cmd()
        cmd_to_run = WhitelistedCommands.oc_cmd_builder(norm_cmd)

        # just exec to cover the case where there is a --follow
        os.execv('/usr/bin/oc', cmd_to_run)

    @staticmethod
    def oc_get_dc_router(occmd):
        ''' oc get dc router (with optional -oyaml or -ojson) '''

        # list of env vars that need redacting
        redact_names = ['STATS_PASSWORD']

        normalized_cmd = occmd.normalized_cmd()
        cmd_to_run = WhitelistedCommands.oc_cmd_builder(normalized_cmd)
        results = subprocess.check_output(cmd_to_run)

        # if we're doing yaml or json output, need to redact output
        if occmd._output_format is not None:
            yaml_results = yaml.load(results)

            WhitelistedCommands.redact_env_values(yaml_results['spec']['template']['spec']['containers'][0]['env'], redact_names)

            if occmd._output_format == 'yaml':
                results = yaml.dump(yaml_results, default_flow_style=False)
            elif occmd._output_format == 'json':
                results = json.dumps(yaml_results, sort_keys=True,
                                     indent=4)

        return results

    @staticmethod
    def oc_get_nodes(occmd):
        normalized_cmd = occmd.normalized_cmd()
        cmd_to_run = WhitelistedCommands.oc_cmd_builder(normalized_cmd)
        results = subprocess.check_output(cmd_to_run)

        return results

    @staticmethod
    def rpm_qa(cmd):
        results = subprocess.check_output(['rpm', '-qa'])
        return results

    @staticmethod
    def tail_var_log_messages(cmd):
        #my_cmd = "oc logs router-3-45nh1 -ndefault --config /home/jdiaz/kubeconfig".split()
        ##results = subprocess.check_output(my_cmd)
        #process = subprocess.Popen(my_cmd, stdout=subprocess.PIPE,
        #                           stderr=subprocess.STDOUT, universal_newlines=True)

        #while True:
        #    out = process.stdout.read(1)
        #    if out == '' and process.poll() != None:
        #        break
        #    if out != '':
        #        sys.stdout.write(out)
        #        sys.stdout.flush()

        #return ""
        #my_cmd = "/usr/bin/sudo /usr/bin/tail -f /var/log/messages".split()
        #os.execv('/usr/bin/sudo', my_cmd)

        my_cmd = "/usr/bin/sudo /home/jdiaz/sudo_commands.py {}".format(cmd).split()
        os.execv('/usr/bin/sudo', my_cmd)
        
class DevGet(object):
    ''' Class to wrap approved developer access commands '''
    def __init__(self):
        self._args = None
        self._user = None
        self._oc_cmd = None

        self.parse_args()
        self.setup_logging()
        logging.debug("Got args: " + str(self._args))

        self._allowed_commands = self.setup_permissions()
        self._command_dict = self.whitelisted_command_list()

    def setup_permissions(self):
        ''' Read in users and roles.
            Return list of allowed commands for user. '''

        perm_dict = yaml.load(open('/home/jdiaz/devget_users.yml','r'))
        # create list of allowed commands for the user
        for user in perm_dict['users']:
            if user['username'] == self._user:
                allowed_roles = user['roles']
        logging.debug("user: {} roles: {}".format(self._user, str(allowed_roles)))
        
        commands = []
        # get list of allowed commands for each role
        for role in perm_dict['roles']:
            if role['name'] in allowed_roles:
                commands.extend(role['commands'])

        logging.debug("user: {} commands: {}".format(self._user, str(commands)))
        return commands
 
    @staticmethod
    def whitelisted_command_list():
        ''' Dict with key of whitelisted commmands mapped to their 
            actual implementation.
            The commands should be in 'normalized' output style from OCCmd.
        '''
        command_dict = {}

        ### original example commands
        command_dict['oc get pods -ndefault'] = WhitelistedCommands.oc_get_pods
        command_dict['oc get pods -ndefault -oyaml'] = WhitelistedCommands.oc_get_pods
        command_dict['oc get pods SUBJECT -ndefault'] = WhitelistedCommands.oc_get_pods
        command_dict['oc get pods SUBJECT -ndefault -oyaml'] = WhitelistedCommands.oc_get_pods
        command_dict['oc get dc router -ndefault'] = WhitelistedCommands.oc_get_dc_router
        command_dict['oc get dc router -ndefault -oyaml'] = WhitelistedCommands.oc_get_dc_router
        command_dict['oc get dc router -ndefault -ojson'] = WhitelistedCommands.oc_get_dc_router
        command_dict['rpm -qa'] = WhitelistedCommands.rpm_qa
        command_dict['tail -f /var/log/messages'] = WhitelistedCommands.tail_var_log_messages
        command_dict['oc get nodes -ndefault -ojson'] = WhitelistedCommands.oc_get_nodes

        #
        # logging
        #
        command_dict['oc get pods -nlogging'] = WhitelistedCommands.oc_get_pods
        command_dict['oc get pods SUBJECT -nlogging'] = WhitelistedCommands.oc_get_pods
        command_dict['oc get pods SUBJECT -nlogging -ojson'] = WhitelistedCommands.oc_get_pods
        command_dict['oc logs SUBJECT -nlogging'] = WhitelistedCommands.oc_get_logs
        command_dict['oc logs SUBJECT -nlogging --follow'] = WhitelistedCommands.oc_get_logs
        command_dict['oc logs SUBJECT -cSUBJECT -nlogging'] = WhitelistedCommands.oc_get_logs
        command_dict['oc logs SUBJECT -cSUBJECT -nlogging --follow'] = WhitelistedCommands.oc_get_logs

        return command_dict

    def parse_args(self):
        ''' Parse command line arguments passed in through the
            SSH_ORIGINAL_COMMAND environment variable when READ_SSH is a
            param.
            Also handle when run manually. '''
        args = None
        user = None
        read_ssh_env = False

        # authorized_keys will force direct our command/argv to be
        # 'remote-healer READ_SSH' with the original params stored
        # in SSH_ORIGINAL_COMMAND
        if "READ_SSH" in sys.argv:
            read_ssh_env = True

        if read_ssh_env:
            cmd = os.environ.get("SSH_ORIGINAL_COMMAND", "")

            # SSH_ORIGINAL_COMMAND will include the whole command
            # as a continuous string
            args = cmd

            # The user's authorized_keys will force the command run to be:
            # <path to devget.py> READ_SSH <username>
            # Save the username for permission lookups later.
            user = sys.argv[2]
        else:
            # not being launched from ssh authorized_keys, so
            # drop the devget.py from the command
            args = " ".join(sys.argv[1:])
            ### XXX: is this the right call to get the username???
            user = os.getlogin()

        self._args = args
        self._user = user

        if self._args.startswith('oc'):
            self._oc_cmd = OCCmd(self._args)

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

    def can_run_cmd(self, cmd):
        ''' Return True/False for whether user is allowed to run the command
        '''
        
        return cmd in self._allowed_commands

    def cmd_not_allowed(self, user_cmd):
        ''' Print generic info when user isnt' able to
            run a command.
        '''

        print "Command not supported/allowed: {}".format(user_cmd)
        print "Allowed commands:"
        for cmd in self._allowed_commands:
            print cmd

    def main(self):
        ''' Entry point for class '''
        cmd = self._args
        logging.info("user: {} command: {}".format(self._user, self._args))

        # if it's a whitelisted command and the user has permissions to run...
        
        # oc commands are handled in a special way, since those
        # whitelisted function handlers expect an OCCmd object to be passed
        if self._oc_cmd is not None:
            generic_cmd = self._oc_cmd.normalized_cmd(generic=True)
            full_cmd = self._oc_cmd.normalized_cmd()
            logging.debug("Normalized cmd: {}".format(full_cmd))

            if self.can_run_cmd(full_cmd):
                results = self._command_dict[full_cmd](self._oc_cmd)
                print results
            elif self.can_run_cmd(generic_cmd):
                results = self._command_dict[generic_cmd](self._oc_cmd)
                print results
            else:
                self.cmd_not_allowed(full_cmd)
        # generic command run handling
        elif self.can_run_cmd(cmd):
            results = self._command_dict[cmd](cmd)
            print results
        else:
            self.cmd_not_allowed(cmd)
 

if __name__ == '__main__':
    devget = DevGet()
    devget.main()
