from abc import ABC, abstractmethod

class LanguageStrategy(ABC):
    """
    An abstract base class for language-specific vulnerability scanning
    and remediation strategies.
    """

    @abstractmethod
    def install_tools(self):
        """
        Install language-specific scanning tools.
        """
        pass

    @abstractmethod
    def run_sca_scan(self, project_dir: str):
        """
        Run a Software Composition Analysis (SCA) scan for dependencies.

        :param project_dir: The root directory of the project to scan.
        :return: A list of vulnerabilities found.
        """
        pass

    @abstractmethod
    def run_sast_scan(self, project_dir: str):
        """
        Run a Static Application Security Testing (SAST) scan on the source code.

        :param project_dir: The root directory of the project to scan.
        :return: A list of vulnerabilities found.
        """
        pass

    @abstractmethod
    def run_tests(self, project_dir: str) -> tuple[bool, str]:
        """
        Run the project's test suite.

        :param project_dir: The root directory of the project.
        :return: A tuple containing a boolean for success and a string for the output.
        """
        pass

    @abstractmethod
    def apply_patch(self, vulnerability_info: dict, project_dir: str):
        """
        Attempt to apply a patch for a given vulnerability.

        :param vulnerability_info: A dictionary containing details of the vulnerability.
        :param project_dir: The root directory of the project.
        :return: A boolean indicating if the patch was successful.
        """
        pass
