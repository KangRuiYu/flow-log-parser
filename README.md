# Flow Log Parser
A simple program for parsing a file containing flow log data and mapping each row to a tag based on a lookup table.

## How to Run
The program was written and ran on Python 3.11.9. Python can be installed from the [Python site](https://www.python.org/downloads/). To run the program, download and run the `flow_log_parser.py` file with Python. The program takes in three arguments:
1. Log path
2. Lookup path
3. Output path

## Tests
The program was tested on basic test cases in `test_flow_log_parser.py` using sample data in `test_inputs/`. The program was tested for:
- Single line data
- Empty data
- Invalid data (missing data)
- Incorrect version
- Rejected data
- Duplicate data
- Correct outputs

## Assumptions
1. Each log row can match with only one tag.
2. Invalid rows in the lookup file are skipped (missing values).
3. Invalid rows in the log file are skipped (missing values, invalid port).
4. Log rows with the incorrect version are skipped. 
5. REJECTED rows are skipped.
6. Non-OK rows are skipped.
7. There is no strict order required for the output file.
8. All other properties for the flow log data is valid (for the sake of time).
