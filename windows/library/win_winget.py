#! /usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = r'''
---
module: win_winget
version_added: '1.0'
short_description: Install packages using winget
description:
  - With this module you can install windows packages and applications using winget
notes:
  - This module supports B(check_mode)
options:
  id:
    description:
    - The id of the package to install.
    - Either this, I(name), or I(packages) must be provided.
    type: str
  name:
    description:
    - The name of the package to install.
    - Either this, I(id), or I(packages) must be provided.
    type: str
  version:
    description:
    - The version of the package to install
    - This option does not do anything if I(state="absent"), or if I(packages) is provided.
    type: str
  source:
    description:
    - The source for the package (winget, msstore, etc).
    - If I(packages) is provided, this is the default source for all the packages.
    type: str
  scope:
    description:
    - The scope for the package (user or machine).
    - If I(packages) is provided, this is the default scope for all the packages.
    type: str
    choices: [ user, machine ]
  override:
    description:
    - Arguments to be passed directly to the installer
    - This option does not do anything if I(state="absent"), or if I(packages) is provided.
    type: str
  state:
    description:
    - Set to C(present) to ensure packages are installed.
    - Set to C(absent) to ensure they are removed.
    - If I(packages) is provided, this is the default state for all the packages.
    type: str
    default: present
    choices: [ absent, present ]
  packages:
    description:
    - A list of the packages to install/uninstall.
    - Either this, I(id), or I(name) must be provided.
    - If this option is provided, then I(source) and I(state) are the default source/state (and I(id), I(name) and I(version) are not used).
    type: list
    elements: dict
    suboptions:
      id:
        description:
        - The id of the package to install.
        - Either this or I(name) must be provided.
        type: str
      name:
        description:
        - The name of the package to install.
        - Either this or I(id) must be provided.
        type: str
      version:
        description:
        - The version of the package to install.
        - This option does not do anything if I(state="absent").
        type: str
      source:
        description:
        - The source for the package (winget, msstore, etc).
        - This overrides I(source) set at the top-level.
        type: str
      scope:
        description:
        - The scope for the package (user or machine).
        - This overrides I(scope) set at the top-level.
        type: str
        choices: [ user, machine ]
      override:
        description:
        - Arguments to be passed directly to the installer
        - This option does not do anything if I(state="absent").
        type: str
      state:
        description:
        - Set to C(present) to ensure package is installed.
        - Set to C(absent) to ensure it is removed.
        - This overrides I(state) set at the top-level.
        type: str
        required: yes
        choices: [ absent, present ]
'''

EXAMPLES = r'''
- name: install latest version of PowerToys
  win_winget:
    id: Microsoft.PowerToys

- name: install latest version of PowerToys from the Microsoft Store
  win_winget:
    name: Microsoft PowerToys
    source: msstore

- name: install specific version of PowerToys
  win_winget:
    id: Microsoft.PowerToys
    version: '0.66.0'

- name: uninstall PowerToys
  win_winget:
    id: Microsoft.PowerToys
    state: absent

- name: install VSCode
  win_winget:
    id: Microsoft.VisualStudioCode
    override: /mergetasks="!runcode,addtopath"
'''

RETURN = r'''
installed:
  description: a list of the packages that were installed
  type: list
  elements: dict
  contains:
    Id:
      description: the package id
      type: str
      returned: always
    Name:
      description: the package name
      type: str
      returned: always
    Source:
      description: the package source
      type: str
      sample: winget
      returned: always
    Version:
      description: the package version
      type: str
      returned: always
  returned: always
  sample:
    - Id: Microsoft.Edge
      Name: 'Microsoft Edge'
      Source: winget
      Version: '108.0.1462.76'
uninstalled:
  description: a list of the packages that were uninstalled
  type: list
  elements: dict
  contains:
    Id:
      description: the package id
      type: str
      returned: always
    Name:
      description: the package name
      type: str
      returned: always
    Source:
      description: the package source
      type: str
      returned: always
      sample: winget
    Version:
      description: the package version
      type: str
      returned: always
  returned: always
  sample:
    - Id: Microsoft.Edge
      Name: 'Microsoft Edge'
      Source: winget
      Version: '108.0.1462.76'
'''

