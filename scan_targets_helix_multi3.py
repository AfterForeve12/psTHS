#
#	Read list of targets and execute specified script in multiple threads (using Python's multiprocessor library).
#   Threads should spawn a batch, powershell, etc script with a hostname/IP as
#   a command line arguement.
#
#	v0.1
#	6/25/13
#
#	Notes


from multiprocessing import Process, Lock, Queue, Value
from optparse import OptionParser
import time
from subprocess import PIPE, Popen
import os.path
import shutil

timeout = 600 # secs  5 minutes
verbose = False

class ScanAgent(Process):
	"""Creates ScanAgent process"""
	def __init__(self, name, script, scriptArgs, workQueue, io_lock, numScanned):
		Process.__init__(self)
		self.name = name
		self.script = script
		self.scriptArgs = scriptArgs
		self.workQueue = workQueue
		self.io_lock = io_lock
		self.numScanned = numScanned
		
	def run(self):
		if verbose:
			with self.io_lock:
				print("Starting " + self.name)
		exitFlag = 0
		while not exitFlag:
			if not self.workQueue.empty():
				try:
					hostname = self.workQueue.get(False)
				except:
					continue

				# Test break condition
				if hostname == None:
					if verbose:
						with self.io_lock:
							print("%s recieved exit signal" % self.name)
					exitFlag = 1
					break
				
				if verbose:	
					with self.io_lock:
						print(self.name + " recieved " + hostname)				
				
				result = scan(self, hostname)

				# Collect output into return Queue
			time.sleep(0.5)	
		return
		
def scan(self, hostname):
	# Begin scan of target
	with self.io_lock:
		self.numScanned.value += 1
		print(str(self.numScanned.value) + ": Surveying: " + self.script + ' ' + hostname + ' ' + self.scriptArgs)
	
	# Call script
	###################
	with open(os.devnull, 'w') as tempf:
		p = Popen(self.script + ' ' + hostname + ' ' + self.scriptArgs, stdout=tempf)
		p.communicate()
		
	#Check for timeout of subprocess
	start_time = time.time()
	while p.poll() == None and time.time() - start_time < timeout:
		time.sleep(10)
	else:
		if p.poll() == None:
			with self.io_lock:
				print("Error in subprocess: Killing thread")
			p.terminate()
			return 1
	return 0
	
def query_yes_no(question, default="yes"):
    """Ask a yes/no question via input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is one of "yes" or "no".
    """
    valid = {"yes":True,   "y":True,  "ye":True,
             "no":False,     "n":False}
    if default == None:
        prompt = "[y/n] "
    elif default == "yes":
        prompt = "[Y/n] "
    elif default == "no":
        prompt = "[y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        print(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            print("Please respond with 'yes' or 'no' "\
                             "(or 'y' or 'n').\n")


def findUniques(seq, idfun=None): 
   # order preserving unique
   # findUniques(a, lambda x: x.lower())
   if idfun is None:
       def idfun(x): return x 
   seen = {}
   result = []
   for item in seq:
       marker = idfun(item)
       if marker in seen: continue
       seen[marker] = 1
       result.append(marker)
   return result
	
def argParser():
	# Parse Command Line Arguments
	usage = "usage: %prog [options] -a <args> -n #"
	parser = OptionParser(usage=usage)
	parser.add_option("-t", "--targets", dest="targetsFile", metavar="FILE", 
				help="Targets File.  Default=targets.txt")	
	parser.add_option("-a", "--args", dest="scriptargs", metavar="FILE", 
				help="Script Arguments")
	parser.add_option("-n", "--nthreads", type="int", dest="nthreads", metavar="#",
				help="Number of threads to execute.  Default=4")
	parser.set_defaults(targetsFile="targets.txt",scriptargs="",nthreads=4)
	(options, args) = parser.parse_args()
	if options.nthreads > 24:
		parser.error('highest number of threads tested is 24.  Please choose less than 24 threads')
		exit(1)
	return (options, args)
	
	
if __name__ == '__main__':

	# Get Current Working Directory of Script
	cwd = os.path.dirname(os.path.realpath(__file__))
	print(os.path.dirname(os.path.realpath(__file__)))
	
	# Parse command line arguments
	(options, args) = argParser()
	script = "Powershell.exe -NoProfile "+cwd+"\Execute-RemoteTask.ps1"
	scriptArgs = options.scriptargs
	threadCount = options.nthreads	
	targetsFile = options.targetsFile
	results = "results.txt"
	
	# Ask if user wants to proceed
	question = "-"*10 + "\nScript:\t\t\"" + script + " <hostname> " + scriptArgs + "\"\n" + "Targets File:\t" + targetsFile + "\n" + "Threads:\t" + str(threadCount) + "\n" + "-"*10 + "\nExecute?\t"
	go = query_yes_no(question)
	if not go:
		exit(0)
	
	# Read Targets List
	targets = set(open(targetsFile).readlines())
	hostTargets = []
	
	for target in targets:
		hostTargets.append(target.strip())
	
	uniqueTargets = findUniques(hostTargets, lambda x: x.upper())
	
	# Creating work queue
	print("Creating work queue")
	workQueue = Queue(0)
	io_lock = Lock()
	numScanned = Value('i',0)
	processes = []
	
	# Create new processes to handle jobs
	print("Creating subprocesses")
	for tName in range(threadCount):
		process = ScanAgent("Process_" + str(tName), script, scriptArgs, workQueue, io_lock, numScanned)
		process.start()
		processes.append(process)
		
	# Fill the queue
	print("Filling work queue: " + str(len(uniqueTargets)) + " hosts")
	for target in uniqueTargets:
		workQueue.put(target.strip())
	
	# Wait for queue to empty
	while not workQueue.empty():
		time.sleep(1)
		pass
		
	with io_lock:
		print("Queue empty. Waiting for last scans to complete")	
	# Notify threads it's time to exit
	for t in processes:
		workQueue.put(None)

	# Wait for all threads to complete (120 second timeout)
	for t in processes:
		t.join(120)
		
	print("Scan Complete.  Exiting Main Thread")

	
# Notes:
		# c = wmi.WMI(hostname, find_classes=False)
		# for i in c.Win32_OperatingSystem(["Caption", "Version", "OSArchitecture"]):
			# output += i + "," 