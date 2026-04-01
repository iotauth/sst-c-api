# How to Enable Metric Logging

To create a CSV log file of the metrics of the current attack, simply add the `-metrics` flag at the end of the run command.

The command should look like: `./client <config_file> <csv_file> -metrics`

# Metric Log Values

For the DoS and DDoS attacks, enabling metric logging will create a CSV file in the `SST_Testbed/metric_logs/` directory that contains information regarding the current execution of `client`. The values stored in the metrics log file are:

1. `exp_id`

    The Experiment ID. This is to differentiate each experiment/attack from one another since there can be multiple attacks during the same execution of `client`.

2. `malicious_number`

    The number of malicious clients participating in the run. This column is left blank by default so it can be filled in manually later for plotting and aggregation.

3. `ts_start`

    The timestamp of the start of the attack, in microseconds. Useful for logging how long the attack took.

4. `ts_end`

    The timestamp of the end of the attack, in microseconds. Useful for logging how long the attack took.

5. `successes`

    The number of times the intended operation succeeeded. The operation is dependent on the attack type that is defined by the user in the `SST_Testbed/csv_files/`.
6. `failures`

    The number of times the intended operation failed. The operation is dependent on the attack type that is defined by the user in the `SST_Testbed/csv_files/`.

7. `avg_us`

    The average duration of the attack performed, in microseconds. This is calculated by taking the duration of each operation during the attack and summing them up. Then, this sum is divided by the total number of attempted operations (`successes` + `failures`).

8. `min_us`

    The duration of the fastest operation during the attack, in microseconds. Useful for logging and comparing against `max_us`.

9. `max_us`

    The duration of the slowest operation during the attack, in microseconds. Useful for logging and comparing against `min_us`.

10. `duration_us`

    The total duration of the attack in microseconds.

11. `attempt_rate_per_s`

    The rate of attempted operations per second during the attack. This is calculated by taking the total number of attempted operations (`successes` + `failures`) and dividing it by the total duration of the attack. This total duration is obtained by subtracting `ts_start` from `ts_end` once the attack has finished.

12. `success_rate_per_s`

    The rate of the successful operations per second during the attack. This is calculated by taking `sucesses` and dividing it by the total duration of the attack. This total duration is obtained by subtracting `ts_start` from `ts_end` once the attack has finished.
