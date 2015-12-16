"""  This is an example Python script that demonstrates how to query for RF Metadata via the RF API
"""
from RFAPI import RFAPI

""" Token and Metadata Query """
TOKEN="<Your Token Here>"
q ={"metadata":{}} 

def print_primitive_or_declared_type(attrs):
    if attrs['type']['kind'] == "primitive" or attrs['type']['kind'] == "declared":
        # Primitive or Declared type attribute.  Print the attribute name and the name of the attribute type 
        print "  "+attrs['name']+": "+attrs['type']['name']

def print_object_type(attrs):
    if attrs['type']['kind'] == "object":
        # Object attribute.  Print attribute name and its type (object) 
        print "  "+attrs['name']+": object"

def get_types_from_list(types_list):
    types = []
    for type in types_list: 
        types.append(type['name'])
    type_list=",".join(types) 
    return type_list 

def print_set_type(attrs):
    # Sets can contain a Union.  Need to check for that. 
    if attrs['type']['kind'] == "set": 
        # Set. Print attribute name, and the name of the type name within the Set attribute itself 
        if 'name' in attrs['type']['type']:
            print "  "+attrs['name']+": set("+attrs['type']['type']['name']+")"
        elif attrs['type']['type']['kind'] == "union": 
            # This is set of a union 
            print "  "+attrs['name']+": set(union("+get_types_from_list(attrs['type']['type']['types'])+"))"
        else:
            print "  "+attrs['name']+": Unknown?"

def print_union_types(attrs):
    union_type =""
    if attrs['type']['kind'] == "union": 
        # Union.  Contains list of types.  Loop over all types 
        union_string = "  "+attrs['name']+" union("+get_types_from_list(attrs['type']['types'])+")"
        print union_string

""" Print out metadata names/type attributes for a parent metadata element """
def print_attributes(attrs):
    print_primitive_or_declared_type(attrs)
    print_object_type(attrs)
    print_set_type(attrs) 
    print_union_types(attrs)

""" Main Routine """
def main():
    # Construct a RFAPI query object 
    rfqapi = RFAPI(TOKEN)

    # Query for the metadata 
    mdata_result = rfqapi.paged_query(q)

    # Loop over all the metadata and each metadata attributes 
    for metadata in mdata_result:
        mdata_types =  metadata['types']
        for md_type in mdata_types:
            # Print each Root Metadata Type 
            parent_type=""
            if 'parent' in md_type:
                parent_type = str(md_type['parent'])
            print md_type['name']+"("+parent_type+")"

            # Loop over attributes in this metadata type and print their corresponding types 
            for md_attr_list in md_type['attrs']:
                print_attributes(md_attr_list)

if __name__ == "__main__":
    main()
