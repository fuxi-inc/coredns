import logging

import dns
import urllib3
from dns import message, query, resolver
import requests
import json

SERVER_ADDR = "106.15.62.126"
BASIC_PORT = 1153
DOH_PORT = 1443

def init():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
    logging.basicConfig(filename='logs/recursive_test.log', level=logging.INFO, format=LOG_FORMAT)

def compareRR(rr1, rr2):
    """
        compare RR in Response with the expected one

        rr1:str
            a resource record in dns response message
        rr2:str
            the corresponding resource record expected
    """
    rr1_values = rr1.split(" ")
    rr2_values = rr2.split(" ")
    for i in range(len(rr1_values)):
        if (i == 6 and rr1_values[3] == "SOA") or i == 1:
            continue
        elif rr1_values[i] != rr2_values[i]:
            return False
    return True

def checkSection(section, exp_rrs):
    """
        check the RRs in Answer/Authority/Additional Section by comparing with expected RRs

        section: list
            Answer/Authority/Additional Section in DNS Response MSG
        exp_rr: str
            expected RRs in Answer/Authority/Additional
    """
    rrs = []
    for i in section:
        for record in i.to_text().strip().split("\n"):
            rrs.append(record)

    rrs.sort()
    exp_rrs.sort()

    if exp_rrs[0] == "" and len(rrs) == 0:
        return True

    if len(exp_rrs) != len(rrs):
        return False

    for index in range(len(rrs)):
        if not compareRR(rrs[index], exp_rrs[index]):
            return False

    return True

def basicFuncTest():
    """
        testing for basic functions of recursive servers
    """

    logging.info("== Testing Basic Func ==")

    self_server = resolver.Resolver()
    self_server.nameservers = [SERVER_ADDR]
    self_server.port = BASIC_PORT
    self_server.timeout = 60
    self_server.lifetime = 60

    input_file = open("dataset/basic_testcase.csv", "r", encoding="utf-8")
    result_file = open("dataset/basic_result.csv", "r", encoding="utf-8")

    testIndex = 0
    for testcase in input_file:
        testIndex += 1

        qname = testcase.split(" ")[0]
        qtype = testcase.split(" ")[1].strip()
        rcode = result_file.readline().strip()

        try:
            request = self_server.resolve(qname, qtype, raise_on_no_answer=False)

        except dns.resolver.NXDOMAIN as e1:
            expect_rr = result_file.readline().strip()
            rr = e1.response(e1.qnames()[0]).authority[0].to_text()
            if not (compareRR(rr, expect_rr) and rcode == "NXDOMAIN"):
                logging.error("testcase {} failed!".format(testIndex))
                print("testcase " + str(testIndex) + " failed!")
            continue

        except dns.resolver.NoNameservers:
            if rcode != "REFUSED":
                logging.error("testcase {} failed!".format(testIndex))
                print("testcase " + str(testIndex) + " failed!")
            continue

        answer_line = result_file.readline().strip().split(";")
        authority_line = result_file.readline().strip().split(";")
        additional_line = result_file.readline().strip().split(";")

        if not (checkSection(request.response.answer, answer_line) \
                and checkSection(request.response.authority, authority_line) \
                and checkSection(request.response.additional, additional_line)):
            logging.error("testcase {} failed!".format(testIndex))
            print("testcase " + str(testIndex) + " failed!")
    logging.info("== Basic Func Test Finished ==")

def basicDoHTest():
    """
        testing for basic DOH functions of recursive servers
    """
    logging.info("== Testing Basic DoH Func ==")

    input_file = open("dataset/basic_testcase.csv", "r", encoding="utf-8")
    result_file = open("dataset/basic_result.csv", "r", encoding="utf-8")

    testIndex = 0
    for testcase in input_file:
        testIndex += 1

        qname = testcase.split(" ")[0]
        qtype = testcase.split(" ")[1].strip()

        # send doh requests
        msg = message.make_query(qname, dns.rdatatype.from_text(qtype))
        response = query.https(msg, SERVER_ADDR, timeout=60, port=DOH_PORT, verify=False)

        # check the response
        expect_rcode = result_file.readline().strip()
        if dns.rcode.to_text(response.rcode()) != expect_rcode:
            logging.error("testcase {} failed!".format(testIndex))
            print("testcase " + str(testIndex) + " failed!")
        else:
            if expect_rcode == "NXDOMAIN":
                expect_rr = result_file.readline().strip()
                rr = response.authority[0].to_text()
                if not compareRR(rr, expect_rr):
                    logging.error("testcase {} failed!".format(testIndex))
                    print("testcase " + str(testIndex) + " failed!")
            elif expect_rcode == "REFUSED":
                continue
            else:
                answer_line = result_file.readline().strip().split(";")
                authority_line = result_file.readline().strip().split(";")
                additional_line = result_file.readline().strip().split(";")

                if not (checkSection(response.answer, answer_line) \
                        and checkSection(response.authority, authority_line) \
                        and checkSection(response.additional, additional_line)):
                    logging.error("testcase {} failed!".format(testIndex))
                    print("testcase " + str(testIndex) + " failed!")
    logging.info("== Basic DoH Test Finished ==")

def cmpJSONRR(rr, exp_rr):
    """
        Comparing the RR in response with the expected one. Both in JSON format.
            - RRs with different TTLs with the expected ones are considered true.
            - SOA RRs with different Serial number with the expected ones are considered true.

        rr: dict
            the RR in response
        exp_rr: dict
            the expected RR
    """
    for key in rr.keys():
        if rr[key] != exp_rr[key] and key != "TTL" and key != "data":
            return False
        if rr[key] != exp_rr[key] and key == "data" and rr["type"] == "SOA":
            rr1_values = rr[key].split(" ")
            rr2_values = exp_rr[key].split(" ")
            for i in range(len(rr1_values)):
                if i != 2 and rr1_values[i] != rr2_values[i]:
                    return False
    return True

def cmpJSONResp(response, expectation):
    """
        Comparing the response with the expected one. Both in JSON format.
            - RRs with different TTLs with the expected ones are considered true.
            - SOA RRs with different Serial number with the expected ones are considered true.
    """

    try:
        json_response = json.loads(response)
    except ValueError:
        # when the testcase does not meet the specification and returns an error,
        # it's not in the JSON format
        if response == expectation:
            return True
        else:
            return False

    json_expectation = json.loads(expectation)
    for key in json_response:
        if json_response[key] != json_expectation[key]:
            if key in ("Question", "Answer", "Authority", "Additional"):
                if key == "Additional":
                    # OPT RR exists when it's newly returned from auth,
                    # OPT RR doesn't exist when it's returned from cache.
                    opt_rr = json.loads("[{\"name\":\".\",\"type\":\"OPT\",\"TTL\":32768,\"data\":\"{flags:do,udp:2048,version:0}\"}]")
                    if json_response[key] is None and not json_expectation[key] == opt_rr:
                        return False
                    elif json_response[key] is not None and json_expectation[key]-json_response[key] != opt_rr:
                        return False
                    else:
                        return True
                if len(json_expectation[key]) != len(json_response[key]):
                    return False
                else:
                    # RRs may be in different orders
                    json_expectation[key].sort(key=lambda x: x["data"])
                    json_response[key].sort(key=lambda x: x["data"])
                    for index in range(len(json_response[key])):
                        if json_response[key][index] != json_expectation[key][index] and not cmpJSONRR(json_response[key][index], json_expectation[key][index]):
                            return False
            else:
                return False
    return True

def DoHJSONTest():
    """
        testing for basic DOH functions of recursive servers
    """
    logging.info("== Testing DoH JSON Func ==")

    input_file = open("dataset/doh_json_testcase.csv", "r", encoding="utf-8")
    result_file = open("dataset/doh_json_result.csv", "r", encoding="utf-8")

    testIndex = 0
    for testcase in input_file:
        testIndex += 1

        qname = testcase.split(";")[0]
        qtype = testcase.split(";")[1]
        is_json = testcase.split(";")[2].strip()

        headers = dict()
        payload = dict()

        if is_json == "true":
            headers["accept"] = "application/dns-json"
        if qname != "":
            payload["name"] = qname
        if qtype != "":
            payload["type"] = qtype

        url = "https://{}/dns-query".format(SERVER_ADDR+":"+str(DOH_PORT))
        try:
            res = requests.get(url, params=payload, headers=headers, stream=True, timeout=60, verify=False)
            exp_result = result_file.readline()

            if not cmpJSONResp(res.content.decode(), exp_result):
                logging.error("testcase {} failed!".format(testIndex))
                print("testcase "+str(testIndex)+" failed!")
        except Exception:
            logging.error("DoH Test Failed", exc_info=True)
            return None
    logging.info("== DoH JSON Test Finished ==")


if __name__ == '__main__':
    init()
    basicFuncTest()
    basicDoHTest()
    DoHJSONTest()
