from abc import ABC, abstractmethod
import argparse
import os
from datetime import datetime
from collections import defaultdict
import json

from tabulate import tabulate


# ==========
# User exceptions
# ==========
class EmptyFileError(Exception):
    def __init__(self, file_path):
        self.file_path = file_path

    def __str__(self):
        return f"The file '{self.file_path}' is empty"


class InvalidLogEntryError(Exception):
    def __init__(self, message, log_entry):
        self.message = message
        self.log_entry = log_entry

    def __str__(self):
        return f"Log entry '{self.log_entry}' is not valid - {self.message}"


# ==========


# ==========
# Command line arguments' type-checking methods
# ==========
# Raises an error if a file's extension is not '.log'
def is_log_file(file_path):
    if not file_path.endswith(".log"):
        raise argparse.ArgumentTypeError(
            f"Invalid file extension for '{file_path}'. Expected '.log'"
        )

    return file_path


# Raises an error if --date argument's value does not match the format
def valid_date(date_str):
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").date()
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid date format: '{date_str}'. Expected 'YYYY-MM-DD'"
        )


# ===========


# ===========
# Specifications
# ============
class Specification(ABC):
    @abstractmethod
    def is_satisfied_by(self, log_entry):
        pass


class UrlAndResponseTimeSpecification(Specification):
    def is_satisfied_by(self, log_entry):
        return "url" in log_entry and "response_time" in log_entry


# ============


# ===========
# Report classes
# ===========
class BaseReport(ABC):
    @abstractmethod
    def __init__(self, spec):
        if not isinstance(spec, Specification):
            raise TypeError("spec must implement Specification")
        self.spec = spec

    # Processes each log entry to collect required data for a report generation
    @abstractmethod
    def process_log_entry(self, log_entry):
        pass

    # Generates a report
    @abstractmethod
    def generate_report(self):
        pass


class AverageReport(BaseReport):
    def __init__(self, spec):
        super().__init__(spec)
        self.stats = defaultdict(lambda: {"total": 0, "accumulated_response_time": 0.0})

    def process_log_entry(self, log_entry):
        if not self.spec.is_satisfied_by(log_entry):
            raise InvalidLogEntryError(
                "Missing required fields 'url' or 'response_time'", log_entry
            )

        handler = log_entry["url"]
        self.stats[handler]["total"] += 1
        self.stats[handler]["accumulated_response_time"] += log_entry["response_time"]

        return self.stats

    def generate_report(self):
        report_data = []
        for handler, info in self.stats.items():
            average_response_time = (
                round(info["accumulated_response_time"] / info["total"], 3)
                if info["total"]
                else 0
            )
            report_data.append([handler, info["total"], average_response_time])

        report_data.sort(key=lambda x: x[1], reverse=True)
        headers = ["handler", "total", "avg_response_time"]

        return tabulate(report_data, headers=headers, showindex="always")


class MaxReport(BaseReport):
    def __init__(self, spec):
        super().__init__(spec)
        self.stats = defaultdict(
            lambda: {"total": 0, "max_response_time": float("-inf")}
        )

    def process_log_entry(self, log_entry):
        if not self.spec.is_satisfied_by(log_entry):
            raise InvalidLogEntryError(
                "Missing required fields 'url' or 'response_time'", log_entry
            )

        handler = log_entry["url"]
        self.stats[handler]["total"] += 1
        self.stats[handler]["max_response_time"] = max(
            self.stats[handler]["max_response_time"], log_entry["response_time"]
        )

        return self.stats

    def generate_report(self):
        report_data = []
        for handler, info in self.stats.items():
            report_data.append([handler, info["total"], info["max_response_time"]])

        report_data.sort(key=lambda x: x[1], reverse=True)
        headers = ["handler", "total", "max_response_time"]

        return tabulate(report_data, headers=headers, showindex="always")


class MinReport(BaseReport):
    def __init__(self, spec):
        super().__init__(spec)
        self.stats = defaultdict(
            lambda: {"total": 0, "min_response_time": float("inf")}
        )

    def process_log_entry(self, log_entry):
        if not self.spec.is_satisfied_by(log_entry):
            raise InvalidLogEntryError(
                "Missing required fields 'url' or 'response_time'", log_entry
            )

        handler = log_entry["url"]
        self.stats[handler]["total"] += 1
        self.stats[handler]["min_response_time"] = min(
            self.stats[handler]["min_response_time"], log_entry["response_time"]
        )

        return self.stats

    def generate_report(self):
        report_data = []
        for handler, info in self.stats.items():
            report_data.append([handler, info["total"], info["min_response_time"]])

        report_data.sort(key=lambda x: x[1], reverse=True)
        headers = ["handler", "total", "min_response_time"]

        return tabulate(report_data, headers=headers, showindex="always")


# ==========


# ==========
# argparse command line parameters
# ==========
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", type=is_log_file, nargs="+", required=True)
    parser.add_argument(
        "--report", type=str, choices=["average", "max", "min"], required=True
    )
    parser.add_argument("--date", type=valid_date)
    return parser.parse_args()


# ==========


# ==========
# Utility methods
# ==========
# Returns a report object of a corresponding report class based on the --report argument value.
def get_report_manager(report_name):
    if report_name == "average":
        return AverageReport(UrlAndResponseTimeSpecification())
    if report_name == "max":
        return MaxReport(UrlAndResponseTimeSpecification())
    if report_name == "min":
        return MinReport(UrlAndResponseTimeSpecification())

    raise ValueError("Unknown report name")


# Checks if a file is empty
def is_empty_file(file_path):
    if os.path.getsize(file_path) == 0:
        return True

    return False


# Checks if there is at least one file empty among --file argument list value
def has_empty_file(file_path_list):
    for file_path in file_path_list:
        if is_empty_file(file_path):
            raise EmptyFileError(file_path)


# Returns a python dict parsed from json string
def get_log_entry_from_json_str(json_str):
    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        raise


# Checks if a log entry's datestamp matches --date argument value if it's present
def is_log_entry_matching_date(log_entry, json_str, target_date):
    if "@timestamp" not in log_entry:
        raise InvalidLogEntryError("Missing '@timestamp' field", json_str)

    try:
        log_entry_date = datetime.fromisoformat(log_entry["@timestamp"])
    except ValueError:
        raise InvalidLogEntryError("Invalid '@timestamp' format", json_str)

    return log_entry_date.date() == target_date


# ==========


# ==========
# Script entry point
# ==========
def main():
    args = parse_args()

    try:
        has_empty_file(args.file)
        report_manager = get_report_manager(args.report)

        for file_path in args.file:
            with open(file_path) as log_file:
                for json_str in log_file:
                    log_entry = get_log_entry_from_json_str(json_str)

                    if args.date and not is_log_entry_matching_date(
                        log_entry, json_str, args.date
                    ):
                        continue

                    report_manager.process_log_entry(log_entry)

        report = report_manager.generate_report()
        print(report)

    except FileNotFoundError as e:
        print(f"FileNotFoundError: {e}")
    except json.JSONDecodeError as e:
        print(f"JSONDecodeError: {e}")
    except argparse.ArgumentTypeError as e:
        print(f"ArgumentTypeError: {e}")
    except EmptyFileError as e:
        print(f"EmptyFileError: {e}")
    except InvalidLogEntryError as e:
        print(f"InvalidLogEntryError: {e}")
    except ValueError as e:
        print(f"ValueError: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()
