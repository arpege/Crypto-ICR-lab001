# ICR - labo 001

## Test suite for the server side
Make sure that all `.py` have execution privilege and python3 is installed on the machine. Run `chmod +x test_server.py && chmod +x server.py` to add privileges.

To run the server test suite :

1. start the server `./server.py`
2. run the test suite `./test_server.py`
 
Test case :

1. Legal message
2. Wrong timestamp
3. Wrong padding
4. Wrong MAC

Output :

```shell
Result expected : OK
[ANSWER IS: OK]

Result expected : WRONG TSP
[ANSWER IS: WRONG TSP]

Result expected : PADDING ERROR
[ANSWER IS: PADDING ERROR]

Result expected : MAC ERROR
[ANSWER IS: MAC ERROR]
```

## Test suite for the client side
Make sure that all `.py` and bash script have execution privilege and python3 is installed on the machine. Run `chmod +x test_client.py && chmod +x client.py` and `chmod +x run_client_test.sh` to add privileges.

The `test_client.py` file is a modified version of the regular server. This version send responses containing volunteers errors to test the reaction of the client. A bash script `run_client_test.sh` is used to make all client's calls.

To run the server test suite :

1. start the server `./test_client.py`
2. run the test suite `./run_client_test.sh`
