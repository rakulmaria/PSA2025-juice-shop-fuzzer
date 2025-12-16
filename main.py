from fuzzingbook.GUIFuzzer import fsm_diagram
from selenium import webdriver
from selenium.common.exceptions import ElementClickInterceptedException, ElementNotInteractableException, NoSuchElementException, StaleElementReferenceException

from JuicyGrammarMiner import JuicyGrammarMiner
from JuicyRunner import JuicyRunner
from JuicyFuzzer import JuicyFuzzer

import shutil
import time

BROWSER = 'chrome'
HEADLESS = True
ITERATIONS = 10
LOG = False
XSS = False

def driver():
    if BROWSER == 'firefox':
        assert shutil.which('geckodriver') is not None, \
            "Please install the 'geckodriver' executable " \
            "from https://github.com/mozilla/geckodriver/releases"
        options = webdriver.FirefoxOptions()
        if HEADLESS:
            options.add_argument("--headless")

        # For firefox, set a higher resolution for our screenshots
        options.set_preference("layout.css.devPixelsPerPx", repr(1.4))
        gui_driver = webdriver.Firefox(options=options)

        gui_driver.set_window_size(1400, 800)

    elif BROWSER == 'chrome':
        assert shutil.which('chromedriver') is not None, \
            "Please install the 'chromedriver' executable " \
            "from https://chromedriver.chromium.org"
        options = webdriver.ChromeOptions()
        if HEADLESS:
            options.add_argument("--headless=new")
        # else:
        #     options.add_experimental_option("detach", True) 

        gui_driver = webdriver.Chrome(options=options)
        gui_driver.set_window_size(1400, 700)
        gui_driver.implicitly_wait(2)

    else:
        assert False, "Select 'firefox' or 'chrome' as browser"

    return gui_driver
    

FILENAME = "log.txt"

def log(*args):
    with open(FILENAME, "a") as f:
        for text in args:
            f.write(text + "\n")

def main():
    print("Hello from psa2025-juice-shop-fuzzer!")
    start = time.time()

    with open(FILENAME, "w") as f:
        f.write("--LOG--\n")

    url = "http://localhost:3000/#/login"
    gui_driver = driver()
    gui_driver.get(url)

    gui_miner = JuicyGrammarMiner(gui_driver, XSS)
    gui_fuzzer = JuicyFuzzer(log, gui_driver, miner=gui_miner, log_gui_exploration=LOG)
    gui_runner = JuicyRunner(log, gui_driver, log_gui_exploration=LOG)

    failed_runs = 0
    error_msgs = []

    try:
        try:
            gui_fuzzer.explore_all(gui_runner)
        except NoSuchElementException:
            pass
        
        mid = time.time()

        for i in range(ITERATIONS):
            if LOG:
                log("---iteration " + str(i))
            
            try:
                error_msg, result = gui_fuzzer.run(gui_runner)
            except NoSuchElementException:
                error_msg, result = "NoSuchElementException", gui_runner.FAIL
            
            if result != gui_runner.PASS:
                if LOG:
                    log(error_msg)
                failed_runs += 1
                error_msgs.append(error_msg)

        end = time.time()
        log("\n--RESULTS--",f"{failed_runs} failed tests out of {ITERATIONS}\n{error_msgs}")
        log(f"elapsed time: {end-start} ms", f"time after exploration: {end-mid} ms", f"average per iteration: {(end-mid)/ITERATIONS} ms")

    except ElementClickInterceptedException:
        print("ElementClickInterceptedException " + gui_driver.current_url)
    except ElementNotInteractableException:
        print("ElementNotInteractableException " + gui_driver.current_url)
    except NoSuchElementException:
        print("NoSuchElementException " + gui_driver.current_url)
    except StaleElementReferenceException:
        print("StaleElementException " + gui_driver.current_url)

    #print(fsm_diagram(gui_fuzzer.grammar))


if __name__ == "__main__":
    main()