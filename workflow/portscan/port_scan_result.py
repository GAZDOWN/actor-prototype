from jsl import Document
from jsl.fields import DictField, StringField, DocumentField


class PortScanPort(Document):
    name = StringField(required=True)
    product = StringField()


class PortScanResult(Document):
     tcp = DictField(pattern_properties={'\\d+': DocumentField(PortScanPort, as_ref=True)}, additional_properties=False)
     udp = DictField(pattern_properties={'\\d+': DocumentField(PortScanPort, as_ref=True)}, additional_properties=False)
