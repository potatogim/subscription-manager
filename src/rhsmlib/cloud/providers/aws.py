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
import json
import os

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

    CLOUD_PROVIDER_TOKEN_TTL = 360  # the value is in seconds

    CLOUD_PROVIDER_SIGNATURE_URL = "http://169.254.169.254/latest/dynamic/instance-identity/signature"

    CLOUD_PROVIDER_SIGNATURE_TYPE = "text/plain"

    COLLECTOR_CONF_FILE = "/etc/rhsm/cloud/providers/aws.conf"

    METADATA_CACHE_FILE = "/var/lib/rhsm/cache/aws_metadata.json"

    TOKEN_CACHE_FILE = "/var/lib/rhsm/cache/aws_token.json"

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
        Get configuration of instance from ini file.
        :return: None
        """
        pass

    def _get_metadata_from_cache(self) -> Union[str, None]:
        """
        Try to get metadata from cache
        :return: None
        """
        return None

    def _is_in_memory_cached_token_valid(self) -> bool:
        """
        Check if cached token is still valid
        :return: True, when cached token is valid; otherwise return False
        """
        if self._token is None or self._token_ctime is None:
            return False

        current_time = time.time()
        if current_time < self._token_ctime + self.CLOUD_PROVIDER_TOKEN_TTL:
            return True
        else:
            return False

    def _write_token_to_cache_file(self) -> None:
        """
        Try to write token to cache file
        :return: None
        """
        if self._token is None:
            return None

        token_cache_content = {
            "ctime": str(self._token_ctime),
            "token": self._token
        }

        log.debug(f'Writing AWS token to file {self.TOKEN_CACHE_FILE}')

        with open(self.TOKEN_CACHE_FILE, "w") as token_cache_file:
            json.dump(token_cache_content, token_cache_file)

        # Only owner (root) should be able to read the token file
        os.chmod(self.TOKEN_CACHE_FILE, 0o600)

    def _get_token_from_cache_file(self) -> Union[str, None]:
        """
        Try to get token from cache file. Cache file is JSON file with following structure:

        {
          "ctime": "1607949565.9036307",
          "token": "ABCDEFGHy0hY_y8D7e95IIx7aP2bmnzddz0tIV56yZY9oK00F8GUPQ=="
        }

        The cache file can be read only by owner.
        :return: String with token or None, when it possible to load token from cache file
        """
        log.debug(f'Reading cache file with AWS token {self.TOKEN_CACHE_FILE}')

        if not os.path.exists(self.TOKEN_CACHE_FILE):
            log.debug(f'Cache file {self.TOKEN_CACHE_FILE} with AWS token does not exist')
            return None

        with open(self.TOKEN_CACHE_FILE, "r") as token_cache_file:
            try:
                cache_file_content = token_cache_file.read()
            except OSError as err:
                log.error('Unable to load token cache file')
                return None
        try:
            cache = json.loads(cache_file_content)
        except json.JSONDecodeError as err:
            log.error(f'Unable to parse token cache file: {self.TOKEN_CACHE_FILE}: {err}')
            return None

        required_keys = ['ctime', 'token']
        for key in required_keys:
            if key not in cache:
                log.error(f'Required key: {key} is not included in token cache file: {self.TOKEN_CACHE_FILE}')
                return None

        try:
            ctime = float(cache['ctime'])
        except ValueError as err:
            log.error(f'Wrong ctime value in {self.TOKEN_CACHE_FILE}')
            return None
        else:
            self._token_ctime = ctime

        if time.time() < ctime + self.CLOUD_PROVIDER_TOKEN_TTL:
            return cache['token']
        else:
            log.debug(f'Cache file AWS token file {self.TOKEN_CACHE_FILE} timed out')
            return None

    def _get_token_from_server(self) -> Union[str, None]:
        """
        Try to get token from server as it si described in this document:

        https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html

        When token is received from server, then the token is also written
        to cache file.

        :return: String of token or None, when it wasn't possible to to get token
        """
        log.debug(f'Requesting AWS token from {self.CLOUD_PROVIDER_TOKEN_URL}')

        headers = {
            'X-aws-ec2-metadata-token-ttl-seconds': str(self.CLOUD_PROVIDER_TOKEN_TTL),
            **self.HTTP_HEADERS
        }
        try:
            response = requests.put(self.CLOUD_PROVIDER_TOKEN_URL, headers=headers)
        except requests.ConnectionError as err:
            log.error(f'Unable to receive token from AWS: {err}')
        else:
            if response.status_code == 200:
                self._token = response.text
                self._token_ctime = time.time()
                self._write_token_to_cache_file()
                return response.text
            else:
                log.error(f'Unable to receive token from AWS; status code: {response.status_code}')
        return None

    def _get_token(self) -> Union[str, None]:
        """
        Try to get token from in-memory cache. When in-memory cache is not valid, then
        try to get token from cache file and when cache file is not valid, then finally
        try to get token from AWS server
        :return: String with token or None
        """
        if self._is_in_memory_cached_token_valid() is True:
            token = self._token
        else:
            token = self._get_token_from_cache_file()
            if token is None:
                token = self._get_token_from_server()
        return token

    def _get_metadata_from_server_imds_v1(self) -> Union[str, None]:
        """
        Try to get metadata from server using IMDSv1
        :return: String with metadata or None
        """
        log.debug(f'Trying to get metadata from {self.CLOUD_PROVIDER_METADATA_URL} using IMDSv1')

        try:
            response = requests.get(self.CLOUD_PROVIDER_METADATA_URL)
        except requests.ConnectionError as err:
            log.debug(f'Unable to get AWS metadata using IMDSv1: {err}')
        else:
            if response.status_code == 200:
                return response.text
            else:
                log.debug(f'Unable to get AWS metadata using IMDSv1: {response.status_code}')

    def _get_metadata_from_server_imds_v2(self) -> Union[str, None]:
        """
        Try to get metadata from server using IMDSv2
        :return: String with metadata or None
        """
        log.debug(f'Trying to get metadata from {self.CLOUD_PROVIDER_METADATA_URL} using IMDSv2')

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
                log.error(f'Unable to get AWS metadata using IMDSv2; status code: {response.status_code}')
        return None

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
        metadata = self._get_metadata_from_server_imds_v1()

        if metadata is not None:
            return metadata

        # When it wasn't possible to get metadata using IMDSv1, then try to get metadata using IMDSv2
        return self._get_metadata_from_server_imds_v2()

    def _get_signature_from_cache_file(self) -> Union[str, None]:
        """
        Try to get signature from cache file
        :return: None
        """
        return None

    def _get_signature_from_server_imds_v1(self) -> Union[str, None]:
        """
        Try to get signature using IMDSv1
        :return: String of signature or None, when it wasn't possible to get signature from server
        """
        log.debug(f'Trying to get signature from {self.CLOUD_PROVIDER_SIGNATURE_URL} using IMDSv1')

        try:
            response = requests.get(self.CLOUD_PROVIDER_SIGNATURE_URL)
        except requests.ConnectionError as err:
            log.debug(f'Unable to get AWS signature using IMDSv1: {err}')
        else:
            if response.status_code == 200:
                return response.text
            else:
                log.debug(f'Unable to get AWS signature using IMDSv1: {response.status_code}')

    def _get_signature_from_server_imds_v2(self) -> Union[str, None]:
        """
        Try to get signature using IMDSv1
        :return: String of signature or None, when it wasn't possible to get signature from server
        """
        return None

    def _get_signature_from_server(self) -> Union[str, None]:
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
        signature = self._get_signature_from_server_imds_v1()

        if signature is not None:
            return signature

        return self._get_signature_from_server_imds_v2()

    def get_metadata(self) -> Union[str, None]:
        """
        Try to get metadata from cache file first. When cache file is not available, then try to
        get metadata from server.
        :return: String with metadata or None
        """
        metadata = self._get_metadata_from_cache()

        if metadata is not None:
            return metadata

        return self._get_metadata_from_server()

    def get_signature(self) -> Union[str, None]:
        """
        Try to get signature from cache file first. When cache file is not available, then try to
        get signature from server.
        :return: None
        """
        signature = self._get_signature_from_cache_file()

        if signature is None:
            signature = self._get_signature_from_server_imds_v1()

        return signature


def _smoke_tests():
    """
    WIP function for smoke testing on AWS cloud
    :return:
    """
    # Gather only information about hardware and virtualization
    from rhsmlib.facts.host_collector import HostCollector
    from rhsmlib.facts.hwprobe import HardwareCollector
    import sys

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    root.addHandler(handler)

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
        _signature = _metadata_collector.get_signature()
        print(f'>>> debug <<< metadata signature: {_signature}')

        _metadata_v2 = _metadata_collector._get_metadata_from_server_imds_v2()
        print(f'>>> debug <<< cloud metadata: {_metadata_v2}')


# Some temporary smoke testing code. You can test this module using:
# sudo PYTHONPATH=./src:./syspurse/src python3 -m rhsmlib.cloud.providers.aws
if __name__ == '__main__':
    _smoke_tests()
