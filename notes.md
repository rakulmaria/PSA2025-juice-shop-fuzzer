# Notes for the project

## Relevant links

- [Solutions to Challenges](https://github.com/Whyiest/Juice-Shop-Write-up/tree/main?tab=readme-ov-file). This might be useful, if we need to lookup solutions to the different challenges.
- [OWASP NodeGoat](https://github.com/OWASP/NodeGoat/tree/master). It was discussed that we might look into this web application

## Supervision

### 25-11-25

- ZAP and BooFuzz. ZAP is fine, BooFuzz is not. Crashing terminal instead of program
  - Not a problem, we can use their results to compare with. Explain access issues to actual tool
- Remember to send link to paper we compare to
- SQL injection rules for grammar
- Add coverage, if possible, to have metrics
- Add a couple of different heuristics, compare them
- But not more important than finding more vulnerabilities, better metric
- Exam: Mostly project-based, but maybe conversation moves further in the course content


### 19-11-25

- Own baseline, no fancy heuristics
- Then implement heuristics, like probabilities (the fancier the better)
- Compare those two
- Compare to ZAP and maybe BackREST
- Ideally, more than just one type of vulnerability, not just SQL injection


### 12-11-25

- No papers to compare, what to do?
  - Still look into papers
  - Baseline: Completely random fuzzing generation
- Code setup done
  - Can make better runner with better outcomes/better oracle
- Report template almost empty, what should the structure of the report be?
  - Template is mainly for format
  - Structure: Introduction, background (SUT and method), methodology (/extending the fuzzer/...), evalution/experiment (with results, unless huge), discussion
  - Related work should be short, if it is even there, maybe keep in introduction, but can be own section
    - Be specific, not just add everything on fuzzing
    - Keep notes on papers, with few sentences on what the papers contain/main points/how relevant it is
  - Background should be written while writing rest, with what is needed for rest of report
  - Consider RQ (2-3, 1 if it is big), they should be in introduction
    - To be answered in paper
