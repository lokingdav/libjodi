import time

def startStopwatch():
    return time.perf_counter()

def endStopwatch(test_name, start, numIters):
    end_time = time.perf_counter()
    duration = end_time - start
    print("\n%s\nTotal: %d runs in %0.1f ms\nAvg: %f"
        % (test_name, numIters, duration * 1000, duration * 1000 / numIters))

def main():
    pass

if __name__ == "__main__":
    main()