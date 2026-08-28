# -*- coding: utf-8 -*-
# This script will collect all vulnerabilites and licenses which have a policy violation.
import json
import logging
import argparse
import sys
import os
import re
import hashlib
import codecs
from blackduck.HubRestApi import HubInstance
from timeit import default_timer as timer
import requests
from datetime import datetime
import urllib3
import version

__author__ = version.__author__
__versionro__ = version.__versionro__

#Global variables
args = "" 
MAX_LIMIT=1000

toolName="Synopsys Black Duck Intelligent"
supportedPackageManagerFiles = ["pom.xml","requirements.txt","package.json","package-lock.json",r".\.csproj",r".\.sln","go.mod","Gopkg.lock","gogradle.lock","vendor.json","vendor.conf"]
dependency_cache = dict()
origins_cache = {}
vulnerability_overviews = []
vulnerabilities_responses = []
urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

def find_file_dependency_file(dependency):
    logging.debug(f"Searching {dependency} from {os.getcwd()}")
    if dependency not in dependency_cache:
        for dirpath, dirnames, filenames in os.walk(os.getcwd(), True):
            re_patterns = []
            for pattern in supportedPackageManagerFiles:
                re_patterns.append(re.compile(pattern))
            dependencyFiles = {e for e in filenames for pattern in re_patterns if re.search(pattern, e)}
            for dependencyFile in dependencyFiles:
                lineNumber = checkDependencyLineNro(f'{dirpath}{os.path.sep}{dependencyFile}', dependency)
                if lineNumber:
                    filepath = dirpath[re.search(re.escape(os.getcwd()), dirpath).end()+1::]
                    if filepath == "":
                        logging.debug(f'dependency {dependency} found from {filepath}{dependencyFile} at line {lineNumber}')
                        dependency_cache[dependency] = {"file": dependencyFile, "line": lineNumber}
                        return dependencyFile, lineNumber
                    else:
                        logging.debug(f'dependency {dependency} found from {filepath}{os.path.sep}{dependencyFile} at line {lineNumber}')
                        dependency_cache[dependency] = {"file": f'{filepath}{os.path.sep}{dependencyFile}', "line": lineNumber}
                        return f'{filepath}{os.path.sep}{dependencyFile}', lineNumber
        logging.debug(f'dependency {dependency} not found!')
    else:
        return dependency_cache[dependency]['file'], dependency_cache[dependency]['line']
    return None, None

def checkDependencyLineNro(filename, dependency):
    with codecs.open(filename, "r", encoding="utf8", errors="ignore") as dependencyFile:
        for num, line in enumerate(dependencyFile, 1):
            if re.search(rf'\b{dependency}\b', line, re.IGNORECASE):
                return num
    return None

def get_Transitive_upgrade_guidance(hub, projectId, projectVersionId, component) -> list:
    global origins_cache
    transitive_guidances = []
    dependency_type = "DIRECT"
    if component and "origins" in component:
        for origin in component["origins"]:
            try:
                origin_url = getLinksparam(origin, "origin", "href")
            except KeyError:
                origin_url = origin["origin"]
            originID = origin_url.split("/")[-1]
            dependency_paths = get_Dependency_paths(hub, projectId, projectVersionId, originID)
            if dependency_paths and dependency_paths['totalCount'] > 0:
                for dependency in dependency_paths['items']:
                    dependency_type = dependency["type"]
                    if dependency["type"] == "TRANSITIVE":
                        if len(dependency.get("path", [])) < 2:
                            logging.warning("Skipping transitive upgrade guidance with incomplete dependency path")
                            continue
                        guidance_component = dependency["path"][-2]
                        guidance_relation = "transitive-upgrade-guidances"
                    else:
                        if not dependency.get("path"):
                            logging.warning("Skipping upgrade guidance with empty dependency path")
                            continue
                        guidance_component = dependency["path"][0]
                        guidance_relation = "upgrade-guidance"

                    origin_id = guidance_component.get("originId")
                    if not origin_id:
                        logging.warning("Skipping upgrade guidance without an origin ID")
                        continue
                    if origin_id not in origins_cache:
                        transitive_guidance = getLinksData(hub, guidance_component, guidance_relation)
                        if transitive_guidance:
                            transitive_guidances.append(transitive_guidance)
                            origins_cache[origin_id] = transitive_guidance
                    else:
                        transitive_guidances.append(origins_cache[origin_id])
    return dependency_type, transitive_guidances

def get_vulnerabilities(hub, projectversion, limit=MAX_LIMIT):
    parameters={"limit": limit, "offset": 0, "filter": "remediationType:affected,remediationType:mitigated,remediationType:needs_review,remediationType:new,remediationType:remediation_complete,remediationType:remediation_required,remediationType:under_investigation"}
    url = projectversion['_meta']['href'] + "/vulnerabilities"
    headers = hub.get_headers()
    headers['Accept'] = 'application/vnd.blackducksoftware.bill-of-materials-8+json'
    response = requests.get(url, headers=headers, params=parameters, verify = not hub.config['insecure'])
    jsondata = response.json()
    total_count = jsondata.get("totalCount", 0)
    vulnerabilities = jsondata.get("items", [])
    offset = limit
    while offset < total_count:
        logging.debug("Getting vulnerabilities page %s/%s", offset, total_count)
        parameters["offset"] = offset
        response = requests.get(url, headers=headers, params=parameters, verify = not hub.config['insecure'])
        vulnerabilities.extend(response.json().get("items", []))
        offset += limit
    jsondata["items"] = vulnerabilities
    return jsondata

def get_Dependency_paths(hub, projectID, projectversionID, originID):
    url = f"{hub.get_urlbase()}/api/project/{projectID}/version/{projectversionID}/origin/{originID}/dependency-paths"
    headers = hub.get_headers()
    headers['Accept'] = 'application/vnd.blackducksoftware.bill-of-materials-7+json'
    response = requests.get(url, headers=headers, verify = not hub.config['insecure'])
    jsondata = response.json()
    return jsondata

def getLinksData(hub, data, relName, headers=None):
    url = getLinksparam(data,relName,"href")
    if url:
        if headers:
            return hub.execute_get(url, custom_headers=headers).json()
        return hub.execute_get(f'{url}?limit={MAX_LIMIT}').json()

def getLinksparam(data, relName, param):
    for metadata in data['_meta']['links']:
        if metadata['rel'] == relName:
            return metadata[param]

def getEPSS_scoring(vulnerability):
    response = requests.get(f'https://api.first.org/data/v1/epss?cve={vulnerability}', verify=False)
    if response.status_code != 200:
        logging.warning("EPSS lookup for %s returned HTTP %s", vulnerability, response.status_code)
        return None, None

    try:
        epss_data = response.json().get("data", [])
    except ValueError:
        logging.warning("EPSS lookup for %s returned invalid JSON", vulnerability)
        return None, None

    if not epss_data:
        logging.info("No EPSS score is available for %s", vulnerability)
        return None, None

    try:
        epssJson = epss_data[0]
        epss = round(float(epssJson["epss"])*100, 3)
        percentile = int(round(float(epssJson["percentile"])*100, 0))
    except (IndexError, KeyError, TypeError, ValueError):
        logging.warning("EPSS lookup for %s returned malformed score data: %s", vulnerability, epss_data)
        return None, None

    logging.info(epssJson)
    return epss, percentile

def addFindings():
    global args
    rules, results, ruleIds = [], [], []
    hub = HubInstance(args.url, api_token=args.token, insecure=False)
    version = hub.get_project_version_by_name(args.project, args.version)
    if version:
        projectVersionId = version["_meta"]["href"].split("/")[-1]
        projectId = version["_meta"]["href"].split("/")[-3]

        vulnerabilities = get_vulnerabilities(hub, version)['items']

        for vuln in vulnerabilities:
            logging.info("Processing vulnerability: %s", vuln["id"])

            vulnerability_data = getLinksData(hub, vuln, "vulnerability")
            vuln["vulnerability_data"] = vulnerability_data

            vulnerability_components = getLinksData(hub, vuln, "vulnerabilities-components")
            vuln["vulnerability_components"] = vulnerability_components

        if getattr(args, "vulnerabilities_output", False):
            try:
                with open("vulnerabilities.json", "w", encoding="UTF-8") as output_file:
                    json.dump(vulnerabilities, output_file, indent=2)
            except OSError as error:
                logging.warning("Could not write vulnerabilities response: %s", error)

        for vuln in vulnerabilities:
            rule, result = {}, {}

            vulnerability = vuln["vulnerability_data"]
            vulnerability_components = vuln["vulnerability_components"]

            if vulnerability_components.get("totalCount", 0) > 0:
                component = vulnerability_components["items"][0]
                componentName = component["componentName"]
                componentVersionName = component["componentVersionName"]

                locations, dependency_tree, dependency_tree_matched = checkLocations(hub, projectId, projectVersionId, component)

                ruleId = f'{vulnerability["name"]}:{componentName}:{componentVersionName}'

                ## Adding vulnerabilities as a rule
                if not ruleId in ruleIds:
                    shortDescription, dependencyType, cisa, helpMarkdown = getHelpMarkdown(hub, projectId, projectVersionId, component, vulnerability, dependency_tree, dependency_tree_matched)
                    rule = {"id":ruleId, "helpUri": vulnerability['_meta']['href'], "shortDescription":{"text":f'{shortDescription}'[:900]},
                        "fullDescription":{"text":f'{vulnerability["description"][:900] if vulnerability["description"] else "-"}', "markdown": f'{vulnerability["description"] if vulnerability["description"] else "-"}'},
                        "help":{"text":f'{vulnerability["description"] if vulnerability["description"] else "-"}', "markdown": helpMarkdown},
                        "properties": {"security-severity": getSeverityScore(vulnerability), "tags": addTags(vulnerability, cisa, dependencyType)},
                        "defaultConfiguration":{"level":nativeSeverityToLevel(getSeverity(vulnerability).lower())}}
                    rules.append(rule)
                    ruleIds.append(ruleId)

                ## Adding results for vulnerabilities
                """
                fullDescription = ""
                if "description" in vulnerability and vulnerability["description"]:
                    fullDescription += vulnerability["description"]
                else:
                    fullDescription += "-"
                result['message'] = {"text": f'{fullDescription[:1000] if not fullDescription == "" else "N/A"}'}
                result['ruleId'] = ruleId
                """

                if locations and len(locations) > 0:
                    result['locations'] = locations
                result['partialFingerprints'] = {"primaryLocationLineHash": hashlib.sha256((f'{vulnerability["name"]}{component["componentName"]}').encode(encoding='UTF-8')).hexdigest()}
                results.append(result)
    return results, rules

def getDependenciesForComponent(hub, projectId, projectVersionId, component):
    dependencies = []
    for origin in component["origins"]:
        try:
            origin_url = getLinksparam(origin, "origin", "href")
        except KeyError:
            origin_url = origin["origin"]
        originID = origin_url.split("/")[-1]
        dependency_paths = get_Dependency_paths(hub, projectId, projectVersionId, originID)
        if dependency_paths and dependency_paths['totalCount'] > 0:
            for dependency in dependency_paths['items']:
                paths = []
                for path in dependency['path']:
                    if "originId" in path and path['originId']:
                        paths.append(path['originId'])
                dependencies.append(paths)
    return dependencies

def checkLocations(hub,projectId,projectVersionId,component):
    matchedFiles = getLinksData(hub, component, "matched-files")
    locations, dependency_tree, dependency_tree_matched = [],[],[]
    if matchedFiles and matchedFiles['totalCount'] > 0:
        for matchFile in matchedFiles['items']:
            fileName = matchFile['filePath']['archiveContext'].split('!')[0]
            if not fileName:
                fileName = matchFile['filePath']['compositePathContext'].split('!')[0]
                if not fileName:
                    fileName = matchFile['filePath']['fileName']
            locations.append({"physicalLocation":{"artifactLocation":{"uri":f'{fileName}'},"region":{"startLine":1}}})
            dependency_tree_matched.append(matchFile['filePath']['compositePathContext'])
    else:
        dependencies = getDependenciesForComponent(hub, projectId, projectVersionId, component)
        if dependencies and len(dependencies) > 0:
            testingDependencies = []
            if len(dependencies[0]) > 1:
                testingDependencies = dependencies[0][-2]
            else:
                testingDependencies = dependencies[0][0]
            componentTofind = None
            if testingDependencies and len(testingDependencies) > 1:
                componentTofind = re.split(r'[:/]',testingDependencies)[-2]
            else:
                componentTofind = re.split(r'[:/]',testingDependencies)[0]
            fileWithPath, lineNumber = find_file_dependency_file(componentTofind.replace("-",r"\-"))
            lineNro = 1
            if lineNumber: 
                lineNro = int(lineNumber)
            if fileWithPath:
                locations.append({"physicalLocation":{"artifactLocation":{"uri": fileWithPath.replace('\\','/')},"region":{"startLine":lineNro}}})
            else:
                locations.append({"physicalLocation":{"artifactLocation":{"uri":packageManagerFile(dependencies)},"region":{"startLine":1}}})
            dependency_tree.extend(dependencies)
        else:
            locations.append({"physicalLocation":{"artifactLocation":{"uri":"not_found_from_package_manager_files"},"region":{"startLine":1}}})
    if not len(locations) > 0:
        locations.append({"physicalLocation":{"artifactLocation":{"uri":"not_found_from_package_manager_files"},"region":{"startLine":1}}})
    return locations, dependency_tree, dependency_tree_matched

def packageManagerFile(dependencies):
    packageManager = dependencies[0][-1].split('-')[-1]
    if packageManager:
        match packageManager:
            case "maven": return "pom.xml"
            case "npm": return "package.json"
            case "pip": return "requirements.txt"
            case _: return "not_found_from_package_manager_files"

def getSeverity(vulnerability):
    if "severity" in vulnerability:
        return vulnerability["severity"]
    elif "cvss4" in vulnerability:
        return vulnerability["cvss4"]["severity"]
    elif "cvss3" in vulnerability:
        return vulnerability["cvss3"]["severity"]
    elif "cvss2" in vulnerability:
        return vulnerability["cvss2"]["severity"]
    else:
        return "unspecified"

def getSeverityScore(vulnerability):
    return f'{vulnerability["overallScore"] if "overallScore" in vulnerability else nativeSeverityToNumber(getSeverity(vulnerability).lower())}'

def getHelpMarkdownTableForCVSS4(vulnerability):
    vector = f'{vulnerability["cvss4"]["vector"] if "vector" in vulnerability["cvss4"] else ""}'
    baseScore = f'{add_square(cvss_severity_rating(vulnerability["cvss4"]["baseScore"])) + " (" + str(vulnerability["cvss4"]["baseScore"]) + ")" if "baseScore" in vulnerability["cvss4"] else ""}'
    attackVector = f'{vulnerability["cvss4"]["attackVector"] if "attackVector" in vulnerability["cvss4"] else ""}'
    userInteraction = f'{vulnerability["cvss4"]["userInteraction"] if "userInteraction" in vulnerability["cvss4"] else ""}'
    attackComplexity = f'{add_reverse_square(vulnerability["cvss4"]["attackComplexity"]) if "attackComplexity" in vulnerability["cvss4"] else ""}'
    attackRequirements = f'{vulnerability["cvss4"]["attackRequirements"] if "attackRequirements" in vulnerability["cvss4"] else ""}'
    privilegesRequired = f'{add_reverse_square(vulnerability["cvss4"]["privilegesRequired"]) if "privilegesRequired" in vulnerability["cvss4"] else ""}'
    subsequentSystemIntegrity = f'{add_square(vulnerability["cvss4"]["subsequentSystemIntegrity"]) if "subsequentSystemIntegrity" in vulnerability["cvss4"] else ""}'
    vulnerableSystemIntegrity = f'{add_square(vulnerability["cvss4"]["vulnerableSystemIntegrity"]) if "vulnerableSystemIntegrity" in vulnerability["cvss4"] else ""}'
    subsequentSystemAvailability = f'{add_square(vulnerability["cvss4"]["subsequentSystemAvailability"]) if "subsequentSystemAvailability" in vulnerability["cvss4"] else ""}'
    vulnerableSystemAvailability = f'{add_square(vulnerability["cvss4"]["vulnerableSystemAvailability"]) if "vulnerableSystemAvailability" in vulnerability["cvss4"] else ""}'
    subsequentSystemConfidentiality = f'{add_square(vulnerability["cvss4"]["subsequentSystemConfidentiality"]) if "subsequentSystemConfidentiality" in vulnerability["cvss4"] else ""}'
    vulnerableSystemConfidentiality = f'{add_square(vulnerability["cvss4"]["vulnerableSystemConfidentiality"]) if "vulnerableSystemConfidentiality" in vulnerability["cvss4"] else ""}'
    exploitMaturity = f'{vulnerability["cvss4"]["exploitMaturity"] if "exploitMaturity" in vulnerability["cvss4"] else ""}'
    nomenclature = f'{vulnerability["cvss4"]["nomenclature"] if "nomenclature" in vulnerability["cvss4"] else ""}'
    tableText = f'## {getNomenclature(nomenclature)} ([CVSS v4.x Metrics](https://www.first.org/cvss/v4-0/specification-document))\n'
    tableText += f'|   |   |   |   |\n'
    tableText += f'| :-- | :-- | :-- | :-- |\n'
    tableText += f'| Attack Vector (AV) | **{attackVector}** | Attack Complexity (AC) | **{attackComplexity}** |\n'
    tableText += f'| Attack Requirements (AT) | **{attackRequirements}** | Privileges Required (PR) | **{privilegesRequired}** |\n'
    tableText += f'| User Interaction (UI) | **{userInteraction}** | Vulnerable System Confidentiality Impact (VC) | **{vulnerableSystemConfidentiality}** |\n'
    tableText += f'| Vulnerable System Integrity Impact (VI) | **{vulnerableSystemIntegrity}** | Vulnerable System Availability Impact (VA) | **{vulnerableSystemAvailability}** |\n'
    tableText += f'| Subsequent System Confidentiality Impact (SC) | **{subsequentSystemConfidentiality}** | Subsequent System Integrity Impact (SI) | **{subsequentSystemIntegrity}** |\n'
    tableText += f'| Subsequent System Availability Impact (SA) | **{subsequentSystemAvailability}** | Exploit Maturity (E) | **{exploitMaturity}** |\n'
    tableText += f'| Base Score | **{baseScore}** | CVSS Nomenclature | **{nomenclature}** |'
    tableText += f'\n\n**CVSS vector:** {vector}'
    return tableText

def getHelpMarkdownTableForCVSS2_3(vulnerability):
    cvss_version = ""
    if "cvss3" in vulnerability:
        cvss_version = "cvss3"
    else:
        cvss_version = "cvss2"
    vector = f'{vulnerability[cvss_version]["vector"] if "vector" in vulnerability[cvss_version] else ""}'
    attackVector = f'{vulnerability[cvss_version]["attackVector"] if "attackVector" in vulnerability[cvss_version] else ""}'
    attackComplexity = f'{add_reverse_square(vulnerability[cvss_version]["attackComplexity"]) if "attackComplexity" in vulnerability[cvss_version] else ""}'
    confidentialityImpact = f'{add_square(vulnerability[cvss_version]["confidentialityImpact"]) if "confidentialityImpact" in vulnerability[cvss_version] else ""}'
    integrityImpact = f'{add_square(vulnerability[cvss_version]["integrityImpact"]) if "integrityImpact" in vulnerability[cvss_version] else ""}'
    availabilityImpact = f'{add_square(vulnerability[cvss_version]["availabilityImpact"]) if "availabilityImpact" in vulnerability[cvss_version] else ""}'
    privilegesRequired = f'{add_reverse_square(vulnerability[cvss_version]["privilegesRequired"]) if "privilegesRequired" in vulnerability[cvss_version] else ""}'
    scope = f'{vulnerability[cvss_version]["scope"] if "scope" in vulnerability[cvss_version] else ""}'
    userInteraction = f'{vulnerability[cvss_version]["userInteraction"] if "userInteraction" in vulnerability[cvss_version] else ""}'
    exploitability = "****"
    remediationLevel = "****"
    reportConfidence = "****"
    impactSubscore = "****"
    exploitabilitySubscore = "****"
    temporalMetrics = "****"
    if "temporalMetrics" in vulnerability[cvss_version]:
        if "exploitability" in vulnerability[cvss_version]['temporalMetrics']:
            exploitability = vulnerability[cvss_version]['temporalMetrics']['exploitability']
        if "remediationLevel" in vulnerability[cvss_version]['temporalMetrics']:
            remediationLevel = vulnerability[cvss_version]['temporalMetrics']['remediationLevel']
        if "reportConfidence" in vulnerability[cvss_version]['temporalMetrics']:
            reportConfidence = vulnerability[cvss_version]['temporalMetrics']['reportConfidence']
        if "score" in vulnerability[cvss_version]['temporalMetrics']:
            temporalMetrics = f'{add_square(cvss_severity_rating(vulnerability[cvss_version]["temporalMetrics"]["score"]))} ({vulnerability[cvss_version]["temporalMetrics"]["score"]})'
    if "impactSubscore" in vulnerability[cvss_version]:
        impactSubscore = f'{add_square(cvss_severity_rating(vulnerability[cvss_version]["impactSubscore"]))} ({vulnerability[cvss_version]["impactSubscore"]})'
    if "exploitabilitySubscore" in vulnerability[cvss_version]:
        exploitabilitySubscore = f'{add_square(cvss_severity_rating(vulnerability[cvss_version]["exploitabilitySubscore"]))} ({vulnerability[cvss_version]["exploitabilitySubscore"]})'
    tableText = f'## Base Score Metrics ({"[CVSS v3.x Metrics](https://www.first.org/cvss/v3.1/specification-document)" if cvss_version == "cvss3" else "[CVSS v2.x Metrics](https://www.first.org/cvss/v2/guide)"})\n'
    tableText += f'|   |   |   |   |\n'
    tableText += f'| :-- | :-- | :-- | :-- |\n'
    tableText += f'| Attack vector | **{attackVector}** | Availability | **{availabilityImpact}** |\n'
    tableText += f'| Attack complexity | **{attackComplexity}** | Confidentiality | **{confidentialityImpact}** |\n'
    tableText += f'| Integrity | **{integrityImpact}** | Scope | **{scope}** |\n'
    tableText += f'| Privileges required | **{privilegesRequired}** | User interaction | **{userInteraction}** |\n'
    tableText += f'| Exploit Code Maturity | **{exploitability}** | Remediation Level | **{remediationLevel}** |\n'
    tableText += f'| Report Confidence | **{reportConfidence}** | Temporal Score | **{temporalMetrics}** |\n'
    tableText += f'| Exploitability Score | **{exploitabilitySubscore}** | Impact | **{impactSubscore}** |'
    tableText += f'\n\n**CVSS vector:** {vector}'
    return tableText

def getNomenclature(nomenclature):
    if nomenclature:
        if nomenclature == "CVSS-B":
            return 'Base metrics (CVSS-B)'
        elif nomenclature == "CVSS-BE":
            return 'Base and Environmental metrics (CVSS-BE)'
        elif nomenclature == "CVSS_BT":
            return 'Base and Threat metrics (CVSS-BT)'
        elif nomenclature == "CVSS-BTE":
            return 'Base, Threat, Environmental metrics (CVSS-BTE)'
    return "Base Score Metrics"

def getHelpMarkdown(hub, projectId, projectVersionId, component, vulnerability, dependency_tree, dependency_tree_matched, policies=None):
    bdsa_link = ""
    messageText = ""
    related_vuln = None
    cisa = False
    epss, percentile = None, None
    shortDescriptionVuln = f'{vulnerability["_meta"]["href"].split("/")[-1]}'
    if vulnerability["source"] == "BDSA":
        bdsa_link = f'[View BDSA record]({vulnerability["_meta"]["href"]}) | '
    elif getLinksparam(vulnerability, "related-vulnerabilities", "label") == "BDSA":
        bdsa_link = f'[View BDSA record]({getLinksparam(vulnerability, "related-vulnerabilities", "href")}) | '
        related_vuln = getLinksparam(vulnerability, "related-vulnerabilities", "href").split("/")[-1]
        shortDescriptionVuln += f'|{related_vuln}'
    cve_link = ""
    if vulnerability["source"] == "NVD":
        cve_link = f'[View CVE record]({vulnerability["_meta"]["href"]})'
        epss, percentile = getEPSS_scoring(vulnerability["name"])
    elif getLinksparam(vulnerability, "related-vulnerability", "label") == "NVD":
        cve_link = f'[View CVE record]({getLinksparam(vulnerability, "related-vulnerability", "href")})'
        related_vuln = getLinksparam(vulnerability, "related-vulnerability", "href").split("/")[-1]
        shortDescriptionVuln += f'|{related_vuln}'
        epss, percentile = getEPSS_scoring(related_vuln)

    messageText += f'**{vulnerability["source"]}** {vulnerability["_meta"]["href"].split("/")[-1]}'

    if related_vuln:
        messageText += f' ({related_vuln})'
    #Adding score
    messageText += f' **Score** { getSeverityScore(vulnerability)}/10'
    if epss and percentile:
        messageText += f'\n**[EPSS Score](https://www.first.org/epss/user-guide):**  {epss}% ({percentile}th percentile)'
    # logging.debug(f'Vulnerability {vulnerability["name"]} EPSS Score: {epss}% ({percentile}th percentile)')

    #Adding link to BD to see the issues
    seeInBD=f'{hub.get_apibase()}/projects/{projectId}/versions/{projectVersionId}/vulnerability-bom?selectedComponent={component["component"].split("/")[-1]}&componentList.q={component["componentName"].replace(" ", "+")}'
    messageText += f"\n\n[Click Here To See More Details in Black Duck SCA]({seeInBD})"

    #Adding dependency tree or location
    if dependency_tree and len(dependency_tree) > 0:
        messageText += "\n\n## Dependency tree\n"
        for dependencyline in dependency_tree:
            intents = ""
            for dependency in dependencyline[::-1]:
                messageText += f'{intents}* {dependency}\n'
                intents += "    "
    if dependency_tree_matched and len(dependency_tree_matched) > 0:
        messageText += "\n\n## </>Source\n"
        for dependencyline in dependency_tree_matched:
            intents = ""
            for dependencies in dependencyline.split('#')[::-1]:
                for dependency in dependencies.split('!/'):
                    if dependency:
                        messageText += f'{intents}* {dependency}\n'
                        intents += "    "

    if "technicalDescription" in vulnerability and vulnerability['technicalDescription']:
        messageText += f'\n\n## Technical Description\n{vulnerability["technicalDescription"] if vulnerability["technicalDescription"] else "-"}\n{bdsa_link if bdsa_link else ""}{cve_link if cve_link else ""}\n\n'
    else:
        #CVEs don't have technical description
        messageText += f'\n\n## Description\n{vulnerability["description"] if vulnerability["description"] else "-"}\n{bdsa_link if bdsa_link else ""}{cve_link if cve_link else ""}\n\n'
    if "cvss4" in vulnerability:
        messageText += getHelpMarkdownTableForCVSS4(vulnerability)
    elif "cvss3" in vulnerability or "cvss2" in vulnerability:
        messageText += getHelpMarkdownTableForCVSS2_3(vulnerability)

    messageText += f'\n\nPublished on {getDate(vulnerability, "publishedDate")}\nLast Modified {getDate(vulnerability,"updatedDate")}\nDisclosure {getDate(vulnerability,"disclosureDate")}\n :pirate_flag: Exploit Available {getDate(vulnerability,"exploitPublishDate")}'
    timeAfter = datetime.now()-datetime.strptime(vulnerability["publishedDate"], "%Y-%m-%dT%H:%M:%S.%fZ")
    messageText += f'\nVulnerability Age {timeAfter.days} Days.'
    # If CISA KEV info exists, then it will be added here
    cve_cisa_kev = None
    if vulnerability["source"] == "BDSA" and getLinksparam(vulnerability, "related-vulnerability", "label") == "NVD":
        #We need to get related CVE to get CISA KEV info
        related_cve = getLinksData(hub, vulnerability, "related-vulnerability")
        if related_cve and "cisa" in related_cve:
            cve_cisa_kev = related_cve["cisa"]
    elif "cisa" in vulnerability:
        cve_cisa_kev = vulnerability["cisa"]
    if cve_cisa_kev:
        cisa =True
        messageText += f'\n\n :warning: **CISA KEV**\n'
        messageText += f'All federal civilian executive branch agencies are required to remediate vulnerabilities in the KEV catalog within prescribed timeframes.\n'
        messageText += f'**{cve_cisa_kev["vulnerabilityName"]}**\n'
        messageText += f'**Added:** {getDate(cve_cisa_kev,"addedDate")}\t**Due Date:** {getDate(cve_cisa_kev,"dueDate")}\n'
        messageText += f'**Action:**\n'
        messageText += f'{cve_cisa_kev["requiredAction"]}'
    messageText += f'\n\n## :arrow_up: Upgrade Recommendation\n'
    dependencyType, transient_upgrade_guidances = get_Transitive_upgrade_guidance(hub, projectId, projectVersionId, component)
    if transient_upgrade_guidances:
        for guidance in transient_upgrade_guidances:
            messageText += f'\n### For Direct Dependency {guidance["componentName"]} {guidance["versionName"]}\n'
            if "shortTerm" in guidance:
                messageText += f'**Short-Term:**\t{guidance["componentName"]} {guidance["shortTerm"]["versionName"] if "versionName" in guidance["shortTerm"] else "-"}\n'
            else:
                messageText += f'**Short-Term:**\t_Not available at this time_\n'
            if "longTerm" in guidance:
                messageText += f'**Long-Term:**\t{guidance["componentName"]} {guidance["longTerm"]["versionName"] if "versionName" in guidance["longTerm"] else "-"}\n'
            else:
                messageText += f'**Long-Term:**\t_Not available at this time_\n'
        messageText += f'\n## Solution\n{vulnerability["solution"] if "solution" in vulnerability and vulnerability["solution"] else "No Solution"}'
    else:
        messageText += f'\n## Solution\n{vulnerability["solution"] if "solution" in vulnerability and vulnerability["solution"] else "No Solution"}'
    messageText += f'\n\n## Workaround\n{vulnerability["workaround"] if "workaround" in vulnerability and vulnerability["workaround"] else "No Workaround"}'

    if policies:
        messageText += "\n\n## Policy violations\n"
        for policy in policies:
            messageText += f'**Policy name:**\t{policy["name"] if "name" in policy else "-"}\n'
            messageText += f'**Policy description:**\t{policy["description"] if "description" in policy else "-"}\n'
            messageText += f'**Policy severity:**\t{policy["severity"] if "severity" in policy else "-"}\n\n'
  
    if vulnerability:
        messageText += "\n\n## References\n"
        for metadata in vulnerability['_meta']['links']:
            if metadata['rel'] == "cwes":
                cwe = metadata["href"].split("/")[-1]
                messageText += f'* Common Weakness Enumeration: [{cwe}](https://cwe.mitre.org/data/definitions/{cwe.split("-")[-1]}.html)\n'
    # METADATA for birectional connection
    messageText += "\n\n## Metadata\n"
    messageText += "**Black Duck Issue Type:** SECURITY\n"
    messageText += f"**Black Duck Project Name:** {args.project}\n"
    messageText += f"**Black Duck Project Version Name:** {args.version}\n"
    messageText += f"**Black Duck Vulnerability Name:** {vulnerability['name']}\n"
    messageText += f"**Black Duck Component Name:** {component['componentName']}\n"
    messageText += f"**Black Duck Component Version:** {component['componentVersionName']}\n"
    if "origins" in component and len(component["origins"]) > 0:
        messageText += f"**Black Duck Component Origin:** {checkOrigin(component)}"
    shortDescription = f"{dependencyType.capitalize()}: {component['componentName']} {component['componentVersionName']} ({shortDescriptionVuln})"
    return shortDescription, dependencyType, cisa, messageText

def getDate(vulnerability, whichDate):
    datetime_to_modify = None
    if whichDate in vulnerability and vulnerability[whichDate]:
       datetime_to_modify = datetime.strptime(vulnerability[whichDate], "%Y-%m-%dT%H:%M:%S.%fZ")
    if datetime_to_modify:
        return datetime.strftime(datetime_to_modify, "%B %d, %Y")
    return "-"

def addTags(vulnerability, cisa, dependencyType):
    tags = []
    if vulnerability:
        if dependencyType and dependencyType == "TRANSITIVE":
            tags.append("transitive_dependency")
        else:
            tags.append("direct_dependency")
        if cisa: tags.append("KEV")
        cvss_version = ""
        if "cvss4" in vulnerability:
            cvss_version = "cvss4"
        elif "cvss3" in vulnerability:
            cvss_version = "cvss3"
        else:
            cvss_version = "cvss2"
        if "exploitPublishDate" in vulnerability and vulnerability["exploitPublishDate"]:
            tags.append("exploit available")
        elif "exploitAvailable" in vulnerability and vulnerability["exploitAvailable"]:
            tags.append("exploit available")
        if "temporalMetrics" in vulnerability[cvss_version]:
            if "score" in vulnerability[cvss_version]['temporalMetrics']:
                tags.append(f'Temporal {cvss_severity_rating(vulnerability[cvss_version]["temporalMetrics"]["score"])}')
        if "temporalMetrics" in vulnerability[cvss_version]:
            if "remediationLevel" in vulnerability[cvss_version]['temporalMetrics']:
                if vulnerability[cvss_version]['temporalMetrics']['remediationLevel'] == "OFFICIAL_FIX":
                    tags.append("patch available")
                elif "solution" in vulnerability and vulnerability["solution"]:
                    tags.append("patch available")
                if vulnerability[cvss_version]['temporalMetrics']['remediationLevel'] == "TEMPORARY_FIX":
                    tags.append("temporary patch available")
                if vulnerability[cvss_version]['temporalMetrics']['remediationLevel'] == "WORKAROUND":
                    tags.append("workaround available")
        if "workaround" in vulnerability and vulnerability["workaround"]:
            if not "workaround available" in tags:
                tags.append("workaround available")
        if "solution" in vulnerability and vulnerability["solution"]:
            tags.append("solution available")
        cwes = []
        for metadata in vulnerability['_meta']['links']:
            if metadata['rel'] == "cwes":
                cwes.append("external/cwe/" + metadata["href"].split("/")[-1].lower())
        tags.extend(cwes)
        
    tags.append("SCA")
    tags.append("security")
    return tags

def checkOrigin(component):
    if "origins" in component:
        if len(component["origins"]) > 0 and "externalId" in component["origins"][0]:
            return component["origins"][0]["externalId"].replace(' ', '_')
    return component["componentName"].replace(' ', '_')

def cvss_severity_rating(score):
    '''
    CVSS 3.1 Qualitative severity rating scale (https://www.first.org/cvss/v3.1/specification-document)
    CVSS 4.0 has same rating scale: https://www.first.org/cvss/v4-0/specification-document
    '''
    if score:
        if score >= 0.1 and score <= 3.9: return "LOW"
        elif score >= 4.0 and score <= 6.9: return "MEDIUM"
        elif score >= 7.0 and score <= 8.9: return "HIGH"
        elif score >= 9.0: return "CRITICAL"
    return "NONE"
            
def add_square(score:str):
    '''
    CVSS 3.1 Qualitative severity rating scale adding square before rating.
    '''
    if score:
        if score.upper()  == "LOW": return ":blue_square: LOW"
        elif score.upper()  == "MEDIUM": return ":yellow_square: MEDIUM"
        elif score.upper()  == "HIGH": return ":orange_square: HIGH"
        elif score.upper()  == "CRITICAL": return ":red_square: CRITICAL"
    return score

def add_reverse_square(score:str):
    '''
    CVSS 3.1 Qualitative severity rating scale adding square before rating.
    '''
    if score:
        if score.upper()  == "NONE": return ":red_square: NONE"
        elif score.upper()  == "LOW": return ":red_square: LOW"
        elif score.upper()  == "MEDIUM": return ":orange_square: MEDIUM"
        elif score.upper()  == "HIGH": return ":blue_square: HIGH"
        elif score.upper()  == "CRITICAL": return ":blue_square: CRITICAL"
    return score

# Changing the native severity into sarif defaultConfiguration level format
def nativeSeverityToLevel(argument): 
    switcher = { 
        "blocker": "error", 
        "critical": "error", 
        "high": "error", 
        "major": "error", 
        "medium": "warning", 
        "minor": "warning", 
        "low": "note",
        "trivial": "note",
        "info": "note",
        "unspecified": "note"
    }
    return switcher.get(argument, "warning")

# Changing the native severity into sarif security-severity format
def nativeSeverityToNumber(argument): 
    switcher = { 
        "blocker": "9.8", 
        "critical": "9.1", 
        "high": "8.9", 
        "major": "8.9", 
        "medium": "6.8", 
        "minor": "6.8", 
        "low": "3.8",
        "trivial": "3.8",
        "info": "1.0",
        "unspecified": "0.0",
    }
    return switcher.get(argument, "6.8")

def getSarifJsonHeader():
    return {"$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json","version":"2.1.0"}

def getSarifJsonFooter(toolDriverName, rules):
    return {"driver":{"name":toolDriverName,"informationUri": f'{args.url if args.url else ""}',"version":__versionro__,"organization":"Synopsys","rules":rules}}

def writeToFile(findingsInSarif, outputFile, mode="w"):
    f = open(outputFile, mode, encoding="UTF-8")
    f.write(json.dumps(findingsInSarif, indent=3))
    f.close()

def str2bool(v):
  return v.lower() in ("yes", "true", "t", "1")

if __name__ == '__main__':
    try:
        start = timer()
        #Initialize the parser
        parser = argparse.ArgumentParser(
            description="Black Duck results to SARIF format."
        )
        #Parse commandline arguments
        parser.add_argument('--url', help="Baseurl for Black Duck Hub", required=True)
        parser.add_argument('--token', help="BD Access token", required=True)
        parser.add_argument('--project', help="BD project name", required=True)
        parser.add_argument('--version', help="BD project version name", required=True)
        parser.add_argument('--outputFile', help="Filename with path where it will be created, example: /tmp/bdFindings.sarif.json \
                                                if outputfile is not given, then json is printed stdout.", required=False)
        parser.add_argument('--log_level', help="Will print more info... default=INFO", default="INFO")
        parser.add_argument('--logFile', help="Filename with path where logs are written", required=False)
        parser.add_argument('--policyCategories', help="Comma separated list of policy categories, which violations will affect. \
            Options are [COMPONENT,SECURITY,LICENSE,UNCATEGORIZED,OPERATIONAL], default=\"SECURITY\"", default="SECURITY")
        parser.add_argument('--policies', help="true, policy information is added", default=False, type=str2bool)
        parser.add_argument('--vulnerabilities_output', help="true, vulnerability responses are written to vulnerabilities.json from the vulnerabilities REST API", default=False, type=str2bool)
        parser.add_argument('--toolNameforSarif', help="Tool name for sarif", default="Synopsys Black Duck Intelligent", required=False)
        args = parser.parse_args()
        #Initializing the logger
        if args.log_level == "9": log_level = "DEBUG"
        elif args.log_level == "0": log_level = "INFO"
        else: log_level = args.log_level
        log_handlers = [logging.StreamHandler(sys.stderr)]
        if args.logFile:
            log_handlers.append(logging.FileHandler(args.logFile, encoding="UTF-8"))
        logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s: %(message)s', handlers=log_handlers, level=log_level)
        #Printing out the version number
        logging.info("Black Duck results to SARIF formatter version: " + __versionro__)
        if logging.getLogger().isEnabledFor(logging.DEBUG): logging.debug(f'Given params are: {args}')
        findings, rules = addFindings()
        sarif_json = getSarifJsonHeader()
        results = {}
        results['results'] = findings
        results['tool'] = getSarifJsonFooter(args.toolNameforSarif, rules)
        runs = []
        runs.append(results)
        sarif_json['runs'] = runs
        if args.outputFile:
            writeToFile(sarif_json, args.outputFile)
        else:
            print(json.dumps(sarif_json, indent=3))
        end = timer()
        logging.info(f"Creating SARIF format took: {end - start} seconds.")
        logging.info("Done")
    except Exception as e:
        logging.exception(e)
        raise SystemError(e)
