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



from rhsmlib.cloud.detector import CloudDetector
from rhsmlib.cloud.collector import CloudCollector


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

    def __init__(self):
        """
        Initialize instance of AWSCloudCollector
        """
        super(AWSCloudCollector, self).__init__()
        self.token = None

    def _get_collector_configuration_from_file(self):
        """
        Get configuration of instance from ini file
        :return: None
        """
        pass

    def _get_metadata_from_cache(self):
        """
        Try to get metadata from cache
        :return: None
        """
        pass

    def _get_metadata_from_server(self):
        """
        Try to get metadata from server as is described in this document:

        https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html

        It is possible to use two versions. We will try to use version IMDSv1 first (this version requires
        only one HTTP request), when the usage of IMDSv1 is forbidden, then we will try to use IMDSv2 version.
        The version requires two requests (get session TOKEN and then get own metadata using token)
        :return: None
        """


    def _get_signature_from_cache_file(self):
        """
        Try to get signature from cache file
        :return: None
        """
        pass

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

    def get_metadata(self):
        """
        Try to get metadata from cache file first. When cache file is not available, then try to
        get metadata from server.
        :return:
        """
        pass

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
    print('>>> debug <<< result: %s, probability: %6.3f' % (_result, _probability))
