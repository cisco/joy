import time


def end_process(process):
    """
    Takes care of the end-of-life stage of a process.
    If the process is still running, end it.
    The process EOL return code is collected and passed back.
    :param process: A python subprocess object, i.e. subprocess.Popen()
    :return: 0 for process success
    """
    if process.poll() is None:
        # Gracefully terminate the process
        process.terminate()
        time.sleep(1)
        if process.poll() is None:
            # Hard kill the process
            process.kill()
            time.sleep(1)
            if process.poll() is None:
                # Runaway zombie process
                return 1
    elif process.poll() != 0:
        # Export process ended with bad exit code
        return process.poll()

    return 0
