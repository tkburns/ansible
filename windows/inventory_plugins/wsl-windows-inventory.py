from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
    name: wsl-windows-inventory
    plugin_type: inventory
    short_description: Dynamically determines IP to reach windows host from wsl
    description: Dynamically determines IP to reach windows host from wsl
    options:
      plugin:
        description: Name of the plugin
        required: true
        choices: ['wsl-windows-inventory']
      group:
        description: Group name for the windows host
        required: true
        type: string
      vars:
        description: The host vars for the windows host
        required: false
'''



from ansible.plugins.inventory import BaseInventoryPlugin
from ansible.errors import AnsibleError, AnsibleParserError
from ansible.module_utils.common.text.converters import to_text
import subprocess


class InventoryModule(BaseInventoryPlugin):
    NAME = 'wsl-windows-inventory'


    def verify_file(self, path):
        '''Return true/false if this is possibly a valid file for this plugin to consume'''
        return super(InventoryModule, self).verify_file(path)
    
    def parse(self, inventory, loader, path, cache):
        '''Return dynamic inventory from source '''
        super(InventoryModule, self).parse(inventory, loader, path, cache)

        # Read the inventory YAML file
        self._read_config_data(path)
        try:
            # Store the options from the YAML file
            self.plugin = self.get_option('plugin')
            self.group = self.get_option('group')
            self.vars = self.get_option('vars')
        except Exception as e:
            raise AnsibleParserError(
                'Required options: {}'.format(e))


        # Get the windows ip (in wsl)
        command = 'cat /etc/resolv.conf | grep nameserver | cut -d " " -f 2'
        child = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        windowsHost = to_text(child.stdout.read().strip())

        # Generate the inventory
        # TODO - support multiple groups?
        # TODO - support other hosts? merge with existing inventory?
        self.inventory.add_group(self.group)
        self.inventory.add_host(windowsHost, group=self.group)
        if self.vars is not None:
            for varKey in self.vars:
                self.inventory.set_variable(windowsHost, varKey, self.vars[varKey])
        # import pdb; pdb.set_trace()

