from jsl import Document
from jsl.fields import BooleanField, StringField
from snactor.registry.schemas import registered_schema

SCHEMA_VERSION_1_0="1.0"

@registered_schema(SCHEMA_VERSION_1_0)
class TypePortScanOptions(Document):
    shallow_scan = BooleanField(required=False)
    port_range = StringField(required=False)
    force_nmap = BooleanField(required=False)
