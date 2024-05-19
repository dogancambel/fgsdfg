import threading
import time

from aaa import perform_two_factor_auth

def main():
    with open('accounts.txt', 'r') as f:
        accounts = f.readlines()

    threads = []

    for account in accounts:
        thread = threading.Thread(target=perform_two_factor_auth, args=(account,))
        threads.append(thread)
        thread.start()

        time.sleep(2)  # İki faktörlü kimlik doğrulama işlemlerini gecikmeli başlatmak için

    for thread in threads:
        thread.join()

if __name__ == '__main__':
    main()
