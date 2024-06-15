from .enums.access_attribute import AccessAttribute

def translate_integers_to_access_attributes(integers):
    translated_values = []
    for integer in integers:
        try:
            access_attribute = AccessAttribute(integer)
            translated_values.append(access_attribute)
        except ValueError:
            # Handle case where integer does not correspond to any AccessAttribute
            translated_values.append(None)  # or any default value or handling logic
    return translated_values