import sys
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
ITERATION = int(sys.argv[1])
MAX_EXPANSION = int(sys.argv[2])
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

def print_results(start, mid, end, failed_runs, error_msgs, expanded):
    print("RESULTS".center(50))
    print("=" * 50)
    
    print(f"\n Test Summary:")
    print(f"   Failed: {failed_runs} / {expanded}")
    
    print(f"\n Errors discovered:")
    print(f"   Unique / Total: {len(set(error_msgs))} / {len(error_msgs)}")
    print(f"   {set(error_msgs)}")
    print(f"   {error_msgs}")
    
    print(f"\n Timing Information:")
    print(f"   Total elapsed time:       {end-start:.4f} s")
    print(f"   Time after exploration:   {end-mid:.4f} s")
    print(f"   Average per iteration:    {(end-mid)/expanded:.4f} s")
    
    print("\n" + "=" * 50 + "\n")

def main():
    print("\n" + "=" * 50)
    print(f"ITERATION NO. {ITERATION}".center(50))
    
    start = time.time()

    url = "http://localhost:3000/#/login"
    gui_driver = driver()
    gui_driver.get(url)

    gui_miner = JuicyGrammarMiner(gui_driver, XSS)
    gui_fuzzer = JuicyFuzzer(gui_driver, miner=gui_miner, log_gui_exploration=LOG)
    gui_runner = JuicyRunner(gui_driver, log_gui_exploration=LOG)

    failed_runs = 0
    error_msgs = []

    try:
        try:
            gui_fuzzer.explore_all(gui_runner)
        except NoSuchElementException:
            pass

        mid = time.time()

        for i in range(1, MAX_EXPANSION+1):
            if LOG:
                print("---iteration " + str(i))

            try:
                error_msg, result = gui_fuzzer.run(gui_runner)
            except NoSuchElementException:
                error_msg, result = "NoSuchElementException", gui_runner.FAIL
            
            if result != gui_runner.PASS:
                if LOG:
                    print(error_msg) 
                failed_runs += 1
                error_msgs.append(error_msg)

        end = time.time()

        print_results(start, mid, end, failed_runs, error_msgs, MAX_EXPANSION)


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