# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 Red Hat, Inc.
#
# This software is licensed to you under the GNU General Public License,
# version 2 (GPLv2). There is NO WARRANTY for this software, express or
# implied, including the implied warranties of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
# along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
#
# Red Hat trademarks are not licensed under GPLv2. No permission is
# granted to use or replicate Red Hat trademarks that are incorporated
# in this software or its documentation.
#

"""
This is module implementing detector and metadata collector of virtual machine running on AWS
"""

import requests
import logging
import time
from typing import Union

from rhsmlib.cloud.detector import CloudDetector
from rhsmlib.cloud.collector import CloudCollector


log = logging.getLogger(__name__)


class AWSCloudDetector(CloudDetector):
    """
    Detector of cloud machine
    """

    ID = 'aws'

    def __init__(self, hw_info):
        """
        Initialize instance of AWSCloudDetector
        """
        super(AWSCloudDetector, self).__init__(hw_info)

    def is_vm(self):
        """
        Is system running on virtual machine or not
        :return: True, when machine is running on VM; otherwise return False
        """
        return super(AWSCloudDetector, self).is_vm()

    def is_running_on_cloud(self):
        """
        Try to guess if cloud provider is AWS using collected hardware information (output of dmidecode,
        virt-what, etc.)
        :return: True, when we detected sign of AWS in hardware information; Otherwise return False
        """

        # The system has to be VM
        if self.is_vm() is False:
            return False
        # This is valid for AWS systems using Xen
        if 'dmi.bios.version' in self.hw_info and 'amazon' in self.hw_info['dmi.bios.version']:
            return True
        # This is valid for AWS systems using KVM
        if 'dmi.bios.vendor' in self.hw_info and 'Amazon EC2' in self.hw_info['dmi.bios.vendor']:
            return True
        # Try to get output from virt-what
        if 'virt.host_type' in self.hw_info and 'aws' in self.hw_info['virt.host_type']:
            return True
        # In other cases return False
        return False

    def is_likely_running_on_cloud(self):
        """
        Return non-zero value, when the machine is virtual machine and it is running on kvm/xen and
        some Amazon string can be found in output of dmidecode
        :return: Float value representing probability that vm is running on AWS
        """
        probability = 0.0

        # When the machine is not virtual machine, then there is probably zero chance that the machine
        # is running on AWS
        if self.is_vm() is False:
            return 0.0

        # We know that AWS uses mostly KVM and it uses Xen in some cases
        if 'virt.host_type' in self.hw_info:
            # It seems that KVM is used more often
            if 'kvm' in self.hw_info['virt.host_type']:
                probability += 0.3
            elif 'xen' in self.hw_info['virt.host_type']:
                probability += 0.2

        # Every system UUID of VM running on AWS EC2 starts with EC2 string. Not strong sign, but
        # it can increase probability a little
        if 'dmi.system.uuid' in self.hw_info and self.hw_info['dmi.system.uuid'].lower().startswith('ec2'):
            probability += 0.1

        # Try to find "Amazon EC2", "Amazon" or "AWS" keywords in output of dmidecode
        found_amazon = False
        found_amazon_ec2 = False
        found_aws = False
        for hw_item in self.hw_info.values():
            if type(hw_item) != str:
                continue
            if 'amazon ec2' in hw_item.lower():
                found_amazon_ec2 = True
            elif 'amazon' in hw_item.lower():
                found_amazon = True
            elif 'aws' in hw_item.lower():
                found_aws = True
        if found_amazon_ec2 is True:
            probability += 0.3
        if found_amazon is True:
            probability += 0.2
        if found_aws is True:
            probability += 0.1

        return probability


class AWSCloudCollector(CloudCollector):
    """
    Class implementing collecting metadata from AWS cloud provider
    """

    CLOUD_PROVIDER_ID = "aws"

    CLOUD_PROVIDER_METADATA_URL = "http://169.254.169.254/latest/dynamic/instance-identity/document"

    CLOUD_PROVIDER_METADATA_TYPE = "application/json"

    CLOUD_PROVIDER_TOKEN_URL = "http://169.254.169.254/latest/api/token"

    CLOUD_PROVIDER_TOKEN_TTL = 360  # value is in seconds

    CLOUD_PROVIDER_SIGNATURE_URL = "http://169.254.169.254/latest/dynamic/instance-identity/signature"

    CLOUD_PROVIDER_SIGNATURE_TYPE = "text/plain"

    COLLECTOR_CONF_FILE = "/etc/rhsm/cloud/providers/aws.conf"

    METADATA_CACHE_FILE = "/etc/"

    HTTP_HEADERS = {
        'user-agent': 'RHSM/1.0'
    }

    def __init__(self):
        """
        Initialize instance of AWSCloudCollector
        """
        super(AWSCloudCollector, self).__init__()
        # In-memory cache of token. The token is simple string
        self._token = None
        # Time, when token was received. The value is in seconds (unix time)
        self._token_ctime = None

    def _get_collector_configuration_from_file(self):
        """
        Get configuration of instance from ini file
        :return: None
        """
        pass

    def _get_metadata_from_cache(self) -> Union[str, None]:
        """
        Try to get metadata from cache
        :return: None
        """
        return None

    def _is_cached_token_valid(self) -> bool:
        """
        Check if cached token is still valid
        :return: True, when cached token is valid; otherwise return False
        """
        if self._token is None or self._token_ctime is None:
            return False

        current_time = time.time()
        if self._token_ctime + self.CLOUD_PROVIDER_TOKEN_TTL < current_time:
            return True
        else:
            return False

    def _get_token_from_server(self) -> Union[str, None]:
        """
        Try to get token from server as it si described in this document
        :return: String of token or None, when it wasn't possible to to get token
        """
        headers = {
            'X-aws-ec2-metadata-token-ttl-seconds': self.CLOUD_PROVIDER_TOKEN_TTL,
            **self.HTTP_HEADERS
        }
        try:
            response = requests.get(self.CLOUD_PROVIDER_TOKEN_URL, headers=headers)
        except requests.ConnectionError as err:
            log.error(f'Unable to receive token from AWS: {err}')
        else:
            if response.status_code == 200:
                self._token = response.text
                self._token_ctime = time.time()
                return response.text
            else:
                log.error(f'Unable to receive token from AWS code: {response.status_code}')
        return None

    def _get_token(self) -> Union[str, None]:
        """
        Try to get token from in-memory cache of from AWS server
        :return: String with token or None
        """
        if self._is_cached_token_valid() is True:
            token = self._token
        else:
            token = self._get_token_from_server()
        return token

    def _get_metadata_from_server(self) -> Union[str, None]:
        """
        Try to get metadata from server as is described in this document:

        https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html

        It is possible to use two versions. We will try to use version IMDSv1 first (this version requires
        only one HTTP request), when the usage of IMDSv1 is forbidden, then we will try to use IMDSv2 version.
        The version requires two requests (get session TOKEN and then get own metadata using token)
        :return: String with metadata or None
        """

        # First try to get metadata using IMDSv1
        try:
            response = requests.get(self.CLOUD_PROVIDER_METADATA_URL)
        except requests.ConnectionError as err:
            log.debug(f'Unable to get AWS metadata using IMDSv1: {err}')
        else:
            if response.status_code == 200:
                return response.text
            else:
                log.debug(f'Unable to get AWS metadata using IMDSv1: {response.status_code}')

        # When it wasn't possible to get metadata using IMDSv1, then try to get metadata using IMDSv2
        token = self._get_token()
        if token is None:
            return None

        headers = {
            'X-aws-ec2-metadata-token': token,
            **self.HTTP_HEADERS
        }
        try:
            response = requests.get(self.CLOUD_PROVIDER_METADATA_URL, headers=headers)
        except requests.ConnectionError as err:
            log.error(f'Unable to get AWS metadata using IMDSv2: {err}')
        else:
            if response.status_code == 200:
                return response.text
            else:
                log.error(f'Unable to get AWS metadata using IMDSv2: {response.status_code}')
        return None

    def _get_signature_from_cache_file(self):
        """
        Try to get signature from cache file
        :return: None
        """
        return None

    def _get_signature_from_server(self):
        """
        Try to get signature from server as is described in this document:

        https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-signature.html

        AWS provides several versions signatures (PKCS7, base64-encoded and RSA-2048). We will use
        the base64-encoded one, because it is easier to send it as part of JSON document. It is
        possible to get signature using IMDSv1 and IMDSv2. We use same approach of obtaining
        signature as we use, when we try to obtain metadata. We try use IMDSv1 first, when not
        possible then we try to use IMDSv2.
        :return: None
        """
        pass

    def get_metadata(self) -> Union[str, None]:
        """
        Try to get metadata from cache file first. When cache file is not available, then try to
        get metadata from server.
        :return: String with metadata or None
        """
        metadata = self._get_metadata_from_cache()

        if metadata is None:
            metadata = self._get_metadata_from_server()

        return metadata

    def get_signature(self):
        """
        Try to get signature from cache file first. When cache file is not available, then try to
        get signature from server.
        :return: None
        """
        pass


# Some temporary smoke testing code. You can test this module using:
# sudo PYTHONPATH=./src:./syspurse/src python3 -m rhsmlib.cloud.providers.aws
if __name__ == '__main__':
    # Gather only information about hardware and virtualization
    from rhsmlib.facts.host_collector import HostCollector
    from rhsmlib.facts.hwprobe import HardwareCollector

    _facts = {}
    _facts.update(HostCollector().get_all())
    _facts.update(HardwareCollector().get_all())
    _aws_cloud_detector = AWSCloudDetector(_facts)
    _result = _aws_cloud_detector.is_running_on_cloud()
    _probability = _aws_cloud_detector.is_likely_running_on_cloud()
    print(f'>>> debug <<< cloud provider: {_result}, probability: {_probability}')

    if _result is True:
        _metadata = None
        _metadata_collector = AWSCloudCollector()
        _metadata = _metadata_collector.get_metadata()
        print(f'>>> debug <<< cloud metadata: {_metadata}')
