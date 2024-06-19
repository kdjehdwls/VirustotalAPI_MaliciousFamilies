import requests
import time
import json
import os
from tqdm import tqdm
import itertools
import sys
import threading

#업로딩중 스피너
def spinner():
    spinner_chars = itertools.cycle(['-', '/', '|', '\\'])
    while not upload_finished:
        sys.stdout.write(next(spinner_chars))
        sys.stdout.flush()
        time.sleep(0.1)
        sys.stdout.write('\b')

def get_upload_url(api_key):
    url = 'https://www.virustotal.com/api/v3/files/upload_url'
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        upload_url = response.json().get('data', '')
        return upload_url
    else:
        print(f"Failed to get upload URL: {response.status_code} - {response.text}")
        return None
#tqdm으로 업로드 진행률 표시. 한번에 올려야돼서 청크로 나누는게 안되기때문에 시각적효과로만
def upload_file(api_key, file_path, upload_url):
    global upload_finished
    upload_finished = False

    headers = {'x-apikey': api_key}
    with open(file_path, 'rb') as file:
        files = {'file': (os.path.basename(file_path), file)}

        
        spinner_thread = threading.Thread(target=spinner)
        spinner_thread.start()

        
        response = requests.post(upload_url, headers=headers, files=files)

        #업로드 완료되고 스피너 종료
        upload_finished = True
        spinner_thread.join()

    # `tqdm`을 사용하여 업로드 완료 시각적 표시
    with tqdm(total=1, desc="File uploaded", unit='file') as pbar:
        pbar.update(1)

    if response.status_code == 200:
        analysis_id = response.json().get('data', {}).get('id') # 웹에는 sha256해시로 검색을하던데 업로드 데이터 전체를 보니 id로 해야하는듯
        print(f"\nAnalysis ID: {analysis_id}")
        return analysis_id
    else:
        print(f"\nFile upload failed: {response.status_code} - {response.text}")
        return None
    
#같은 코드인데도 리포트를 못받을때가 있다 이상. 딜레이 없이 받을때 / 타임아웃으로 나뉘는듯
def get_report(api_key, analysis_id):
    url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to get report: {response.status_code} - {response.text}")
        return None

#popular threat은 api로 구현이 되어있다
def get_popular_threat_categories(api_key):
    url = "https://www.virustotal.com/api/v3/popular_threat_categories"
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        categories = response.json()
        categories_str = json.dumps(categories, indent=4)
        print("Popular Threat Categories:")
        print(categories_str)  # 콘솔
        
        with open('popular_threat_categories.txt', 'w') as file: # +파일
            file.write(categories_str)
        print("Popular threat categories saved to popular_threat_categories.txt")
    else:
        print(f"Failed to get popular threat categories: {response.status_code} - {response.text}")

#악성코드 패밀리 식별은 없어서 리포트에서 따로 추출
def extract_malicious_families(report):
    results = report.get('data', {}).get('attributes', {}).get('results', {})
    families = []

    for engine, result in results.items(): #엔진 _ 
        if result.get('category') == 'malicious':
            family_info = result.get('result', '')
            if family_info:  # 결과가 있는 경우에만 추가
                families.append(family_info)

    # 중복 제거 및 정렬
    unique_families = sorted(set(families))

    # 파일만
    with open('malicious_families.txt', 'w') as file:
        for family in unique_families:
            file.write(f"{family}\n")

    print("Malicious families saved to malicious_families.txt")

#리포트 못받아올때가 있어서 추가
def wait_for_completion(api_key, analysis_id, timeout=300, interval=15):
    url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
    headers = {'x-apikey': api_key}

    start_time = time.time()
    while True:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            if result.get('data', {}).get('attributes', {}).get('status') == 'completed':
                return result  # 완료 때 반환하게
            elif time.time() - start_time > timeout:
                print("Timeout waiting for analysis completion.")
                return None  # 일단 타임아웃 시 None
        else:
            print(f"Failed to get analysis status: {response.status_code} - {response.text}")
            return None

        print("Analysis not completed yet. Waiting...")
        time.sleep(interval)  # interval만큼 대기 후 다시 확인

def upload_and_get_report(api_key, file_path):
    upload_url = get_upload_url(api_key)
    if not upload_url:
        print("Failed to obtain upload URL.")
        return

    analysis_id = upload_file(api_key, file_path, upload_url)
    if not analysis_id:
        print("Failed to upload file.")
        return

    report = wait_for_completion(api_key, analysis_id)
    # Wait for some time to allow analysis to complete
    # print("Waiting for analysis to complete...")
    # time.sleep(60)  # Adjust this delay as necessary
    # report = get_report(api_key, analysis_id)
    if report:
        print("Report retrieved successfully.")
        # 보고서를 JSON 문자열로 변환
        report_str = json.dumps(report, indent=4)
        
        # +파일
        with open('report.txt', 'w') as file:
            file.write(report_str)
        
        print("Report saved to report.txt")
        get_popular_threat_categories(api_key)
        extract_malicious_families(report)
        return report
    else:
        print("Failed to retrieve report.")
        return None

# Usage 추가 구현시 main으로 
api_key = ' your key'
file_path = 'your file path'
report = upload_and_get_report(api_key, file_path)
if report:
    print(report) # 추가 구현해보기
