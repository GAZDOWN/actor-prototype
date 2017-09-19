from jsl import Document, Scope
from jsl.fields import ArrayField, StringField
from snactor.registry.schemas import registered_schema


SCHEMA_VERSION_1_0="1.0"


# Type
@registered_schema(SCHEMA_VERSION_1_0, "1.1")
class TypeStringList(Document):
    value = ArrayField(items=StringField(), unique_items=True, additional_items=False)


SCHEMA=TypeStringList
