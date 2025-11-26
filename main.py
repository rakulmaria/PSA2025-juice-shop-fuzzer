from fuzzingbook.GUIFuzzer import fsm_diagram
from selenium import webdriver
from selenium.common.exceptions import ElementClickInterceptedException, ElementNotInteractableException, NoSuchElementException, StaleElementReferenceException

from JuicyGrammarMiner import JuicyGrammarMiner
from JuicyRunner import JuicyRunner
from JuicyFuzzer import JuicyFuzzer

import shutil

BROWSER = 'chrome'
HEADLESS = True
ITERATIONS = 5

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
    

def main():
    print("Hello from psa2025-juice-shop-fuzzer!")

    url = "http://localhost:3000/#/login"
    gui_driver = driver()
    gui_driver.get(url)

    gui_miner = JuicyGrammarMiner(gui_driver)
    gui_fuzzer = JuicyFuzzer(gui_driver, miner=gui_miner, log_gui_exploration=False)
    gui_runner = JuicyRunner(gui_driver)

    failed_runs = 0
    error_msgs = []

    try:
        gui_fuzzer.explore_all(gui_runner)

        for i in range(ITERATIONS):
            #print("---iteration " + str(i))
            error_msg, result = gui_fuzzer.run(gui_runner)
            if result != gui_runner.PASS:
                #print(error_msg)
                failed_runs += 1
                error_msgs.append(error_msg)

        print(f"{failed_runs} failed tests out of {ITERATIONS}\n{error_msgs}")

    except ElementClickInterceptedException:
        print("ElementClickInterceptedException")
    except ElementNotInteractableException:
        print("ElementNotInteractableException")
    except NoSuchElementException:
        print("NoSuchElementException")
    except StaleElementReferenceException:
        print("StaleElementException")

    #print(fsm_diagram(gui_fuzzer.grammar))


if __name__ == "__main__":
    main()