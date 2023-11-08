import logging


def log(LoggerName, LogFile=None):
	# .debug .info .warning .error .critical
	# Create a logger for your script
	logger = logging.getLogger(LoggerName)
	logger.setLevel(logging.DEBUG)  # Set the log level to DEBUG
	formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

	if LogFile:
		# Create a file handler for writing log messages to a file
		file_handler = logging.FileHandler(LogFile)
		file_handler.setLevel(logging.DEBUG)  # Set the desired log level
		file_handler.setFormatter(formatter)
		logger.addHandler(file_handler)  

	# Create a stream handler for displaying log messages on the console
	stream_handler = logging.StreamHandler()
	stream_handler.setLevel(logging.DEBUG)  # Set the desired log level
	stream_handler.setFormatter(formatter)
	logger.addHandler(stream_handler)
	
	return logger
