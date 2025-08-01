import argparse
from datetime import datetime
import json
import sys

import pytest

from main import (
    is_log_file,
    valid_date,
    is_empty_file,
    has_empty_file,
    EmptyFileError,
    get_log_entry_from_json_str,
    is_log_entry_matching_date,
    InvalidLogEntryError,
    get_report_manager,
    AverageReport,
    MaxReport,
    MinReport,
    UrlAndResponseTimeSpecification,
    parse_args,
)


# ==========
# Command line arguments' type-checking methods tests
# ==========
def test_is_log_file():
    assert is_log_file("example.log") == "example.log"


def test_is_log_file_error():
    with pytest.raises(argparse.ArgumentTypeError):
        is_log_file("example.txt")


def test_valid_date():
    date = valid_date("2025-06-22")
    assert date == datetime(2025, 6, 22).date()


def test_valid_date_error():
    with pytest.raises(argparse.ArgumentTypeError):
        valid_date("22-06-2025")


# ==========


# ==========
# Utility methods tests
# ==========
def test_is_empty_file(tmp_path):
    not_empty_file = tmp_path / "not_empty_file.log"
    not_empty_file.write_text("File content")

    assert not is_empty_file(str(not_empty_file))

    empty_file = tmp_path / "empty_file.log"
    empty_file.write_text("")

    assert is_empty_file(str(empty_file))


def test_has_empty_file(tmp_path):
    not_empty_file = tmp_path / "not_empty_file.log"
    not_empty_file.write_text("File content")

    has_empty_file([str(not_empty_file)])


def test_has_empry_file_error(tmp_path):
    not_empty_file = tmp_path / "not_empty_file.log"
    not_empty_file.write_text("File content")

    empty_file = tmp_path / "empty_file.log"
    empty_file.write_text("")

    with pytest.raises(EmptyFileError) as e:
        has_empty_file([str(not_empty_file), str(empty_file)])

    assert str(empty_file) in str(e.value)


def test_get_log_entry_from_json_str():
    get_log_entry_from_json_str_parsed_result = {
        "@timestamp": "2025-06-22T13:57:32+00:00",
        "status": 200,
        "url": "/api/context/...",
        "request_method": "GET",
        "response_time": 0.024,
        "http_user_agent": "...",
    }
    json_str = '{"@timestamp": "2025-06-22T13:57:32+00:00", "status": 200, "url": "/api/context/...", "request_method": "GET", "response_time": 0.024, "http_user_agent": "..."}'
    entry_log = get_log_entry_from_json_str(json_str)

    assert get_log_entry_from_json_str_parsed_result == entry_log


def test_get_log_entry_from_json_str_error():
    with pytest.raises(json.JSONDecodeError):
        get_log_entry_from_json_str("{Invalid JSON}")


def test_is_log_entry_matching_date():
    today = datetime.now().date()
    timestamp = today.isoformat()
    log_entry = {"@timestamp": timestamp}

    assert is_log_entry_matching_date(log_entry, "2025-06-22", today)


def test_is_log_entry_matching_error_missing_stampdate():
    entry_log = {
        "status": 200,
        "url": "/api/context/...",
        "request_method": "GET",
        "response_time": 0.024,
        "http_user_agent": "...",
    }
    json_str = '{"status": 200, "url": "/api/context/...", "request_method": "GET", "response_time": 0.024, "http_user_agent": "..."}'

    with pytest.raises(InvalidLogEntryError) as e:
        is_log_entry_matching_date(entry_log, json_str, "2025-06-22")

    assert "Missing '@timestamp' field" in str(e.value)


def test_is_log_entry_matching_error_invalid_stampdate():
    entry_log = {
        "@timestamp": "22-06-2025T13:57:32+00:00",
        "status": 200,
        "url": "/api/context/...",
        "request_method": "GET",
        "response_time": 0.024,
        "http_user_agent": "...",
    }
    json_str = '{"@timestamp": "22-06-2025T13:57:32+00:00", "status": 200, "url": "/api/context/...", "request_method": "GET", "response_time": 0.024, "http_user_agent": "..."}'

    with pytest.raises(InvalidLogEntryError) as e:
        is_log_entry_matching_date(entry_log, json_str, "2025-06-22")

    assert "Invalid '@timestamp' format" in str(e.value)


def test_get_report_manager():
    average_report = get_report_manager("average")
    assert isinstance(average_report, AverageReport)

    max_report = get_report_manager("max")
    assert isinstance(max_report, MaxReport)

    min_report = get_report_manager("min")
    assert isinstance(min_report, MinReport)


def test_get_report_manager_error():
    with pytest.raises(ValueError):
        get_report_manager("unknown")


# ==========


# ==========
# Report classes tests
# ==========
def test_average_report_process_entry_log():
    report_manager = AverageReport(UrlAndResponseTimeSpecification())
    entry_logs = [
        {
            "@timestamp": "2025-06-22T13:57:32+00:00",
            "status": 200,
            "url": "/api/context/...",
            "request_method": "GET",
            "response_time": 0.024,
            "http_user_agent": "...",
        },
        {
            "@timestamp": "2025-06-22T13:57:32+00:00",
            "status": 200,
            "url": "/api/context/...",
            "request_method": "GET",
            "response_time": 0.02,
            "http_user_agent": "...",
        },
        {
            "@timestamp": "2025-06-22T13:57:32+00:00",
            "status": 200,
            "url": "/api/homeworks/...",
            "request_method": "GET",
            "response_time": 0.06,
            "http_user_agent": "...",
        },
    ]

    for entry_log in entry_logs:
        report_manager.process_log_entry(entry_log)
    report = report_manager.generate_report()

    assert "/api/context/..." in report and "/api/homeworks/..." in report
    assert "0.022" in report and "0.06" in report


def test_max_report_process_entry_log():
    report_manager = MaxReport(UrlAndResponseTimeSpecification())
    entry_logs = [
        {
            "@timestamp": "2025-06-22T13:57:32+00:00",
            "status": 200,
            "url": "/api/context/...",
            "request_method": "GET",
            "response_time": 0.024,
            "http_user_agent": "...",
        },
        {
            "@timestamp": "2025-06-22T13:57:32+00:00",
            "status": 200,
            "url": "/api/context/...",
            "request_method": "GET",
            "response_time": 0.02,
            "http_user_agent": "...",
        },
        {
            "@timestamp": "2025-06-22T13:57:32+00:00",
            "status": 200,
            "url": "/api/homeworks/...",
            "request_method": "GET",
            "response_time": 0.06,
            "http_user_agent": "...",
        },
    ]

    for entry_log in entry_logs:
        report_manager.process_log_entry(entry_log)
    report = report_manager.generate_report()

    assert "/api/context/..." in report and "/api/homeworks/..." in report
    assert "0.024" and "0.06" in report


def test_min_report_process_entry_log():
    report_manager = MinReport(UrlAndResponseTimeSpecification())
    entry_logs = [
        {
            "@timestamp": "2025-06-22T13:57:32+00:00",
            "status": 200,
            "url": "/api/context/...",
            "request_method": "GET",
            "response_time": 0.024,
            "http_user_agent": "...",
        },
        {
            "@timestamp": "2025-06-22T13:57:32+00:00",
            "status": 200,
            "url": "/api/context/...",
            "request_method": "GET",
            "response_time": 0.02,
            "http_user_agent": "...",
        },
        {
            "@timestamp": "2025-06-22T13:57:32+00:00",
            "status": 200,
            "url": "/api/homeworks/...",
            "request_method": "GET",
            "response_time": 0.06,
            "http_user_agent": "...",
        },
    ]

    for entry_log in entry_logs:
        report_manager.process_log_entry(entry_log)
    report = report_manager.generate_report()

    assert "/api/context/..." in report and "/api/homeworks/..." in report
    assert "0.02" and "0.06" in report


def test_average_report_process_entry_log_error():
    report = AverageReport(UrlAndResponseTimeSpecification())

    with pytest.raises(InvalidLogEntryError):
        report.process_log_entry({"Invalid_key:" "Invalid_value"})


def test_max_report_process_entry_log_error():
    report = MaxReport(UrlAndResponseTimeSpecification())

    with pytest.raises(InvalidLogEntryError):
        report.process_log_entry({"Invalid_key:" "Invalid_value"})


def test_min_report_process_entry_log_error():
    report = MinReport(UrlAndResponseTimeSpecification())

    with pytest.raises(InvalidLogEntryError):
        report.process_log_entry({"Invalid_key:" "Invalid_value"})


# ==========


# ==========
# Command line interface  tests
# ==========
def test_parse_args(monkeypatch):
    monkeypatch.setattr(
        sys, "argv", ["prog", "--file", "example.log", "--report", "average"]
    )
    args = parse_args()

    assert args.file == ["example.log"]
    assert args.report == "average"


def test_parse_args_with_date(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "prog",
            "--file",
            "example.log",
            "--report",
            "average",
            "--date",
            "2025-06-22",
        ],
    )
    args = parse_args()

    assert args.file == ["example.log"]
    assert args.report == "average"
    assert args.date == datetime(2025, 6, 22).date()


def test_parse_args_error(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["prog", "--file", "example.log"])

    with pytest.raises(SystemExit):
        parse_args()


# ==========
