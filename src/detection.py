import os
from typing import List

# Mapping of key files to language identifiers
LANGUAGE_INDICATORS = {
    'pom.xml': 'java',
    'build.gradle': 'java',
    'package.json': 'javascript'
}

def detect_project_languages(directory: str) -> List[str]:
    """
    Detects the programming languages of a project in a given directory.

    It walks through the directory and looks for key files that indicate
    the presence of a particular language or build system.

    :param directory: The path to the project's root directory.
    :return: A list of unique language identifiers found (e.g., ['java', 'javascript']).
    """
    detected_languages = set()
    for root, _, files in os.walk(directory):
        for file in files:
            if file in LANGUAGE_INDICATORS:
                language = LANGUAGE_INDICATORS[file]
                detected_languages.add(language)

    return list(detected_languages)
