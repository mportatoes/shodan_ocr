import requests
import argparse
import sys
import os
import time
import boto3

requests.packages.urllib3.disable_warnings() 

#Script Arguments
parser = argparse.ArgumentParser(description="AWS Rekognition API Client")
parser.add_argument('-o', '--obj', required=False,action='store_true', help='Call the AWS object detection API')
parser.add_argument('-t', '--text',required=False,action='store_true',help='Call the AWS OCR API')
parser.add_argument('-d', '--directory',required=False,help='Directory of images')
parser.add_argument('-s', '--shodan',required=False,help='Lookup IP address in Shodan and send directly to Rekognition')
args = parser.parse_args()

#Initialize an empty array to store the images for us to lookup
image_list = []
shodan_api_key = "YOUR_API_KEY"

#Function for collecting image names for lookup
def get_images(directory):
	cur = os.getcwd()
	print cur
	directory = str(cur)+"/"+directory
	for i in os.listdir(directory):
		image_list.append(directory+i)
	return image_list

#Function for calling the Text Detection API
def detect_text(image):
	imageFile = image	
	rekognition = boto3.client("rekognition", "us-east-1")
	with open(imageFile, 'rb') as image:
		response = rekognition.detect_text(Image={'Bytes':image.read()})
	return response['TextDetections']

#Function for calling the Object Detection API
def detect_labels(image):
	imageFile = image	
	rekognition = boto3.client("rekognition", "us-east-1")
	with open(imageFile, 'rb') as image:
		response = rekognition.detect_labels(Image={'Bytes':image.read()})
	return response['Labels']


def shodan_lookup(ip,shodan_api_key):
	r = requests.get("https://api.shodan.io/shodan/host/{1}?key={0}".format(shodan_api_key,ip))
	if r.status_code == 200:
		shodan_data = r.json()
		imageFile = shodan_parse(shodan_data)
		rekognition = boto3.client("rekognition", "us-east-1")
		with open(imageFile, 'rb') as image:
			rek_response = rekognition.detect_text(Image={'Bytes':image.read()})
			#print rek_response
			for k in rek_response['TextDetections']:
				if k['Type'] == "WORD":
					ftext = str(k['DetectedText'])
					fconf = str(k['Confidence'])
					print "{0},{1},{2},WORD".format(ip,ftext,fconf)
					#oFile.write("{0}|{1}|{2}|WORD\n".format(image,ftext,fconf))
				elif k['Type'] == "LINE":
					ftext = str(k['DetectedText'])
					fconf = str(k['Confidence'])
					print "{0},{1},{2},LINE".format(ip,ftext,fconf)
					#oFile.write("{0}|{1}|{2}|LINE\n".format(image,ftext,fconf))
		
	else:
		print "[-] There was an error with "+ip

def shodan_parse(shodan_data):
	if "data" in shodan_data:
		for j in shodan_data['data']:
			if "opts" in j:
				if "screenshot" in j['opts']:
					img_data = str(j['opts']['screenshot']['data'])
					ifile = ip+".jpg"
					with open(ifile,"wb") as img_file:
						img_file.write(img_data.decode('base64'))
						print "[+] Image written to "+ip+".jpg"
						print "[+] Looking up in AWS..."
	return ifile

#If -s is provided, look up the IP address in shodan, grab the base64 image, and send to AWS OCR
if args.shodan:
	if shodan_api_key == "":
		print "[-] Shodan API key not provided...exiting"
		sys.exit()
	ip = str(args.shodan)
	#try:
	shodan_lookup(ip,shodan_api_key)
	#except:
	#	print "Mistakes were made..."
	#	pass

#Make sure a valid directory was provided
if args.directory:
	try:
		directory = args.directory
		get_images(directory)
		print "[+] Directory found, adding images to list..."
		print "[+] Added {0} images to lookup...".format(str(len(image_list)))
	except:
		print "[-] Oops, looks like that directory can't be found, exiting"
		sys.exit()

#Call the Detected Text API
if args.text:
	oFile=open('text-'+str(time.time())+'.csv','w')
	for image in image_list:
		try:
			rek_response = detect_text(image)
			for j in rek_response:
				if j['Type'] == "WORD":
					ftext = str(j['DetectedText'])
					fconf = str(j['Confidence'])
					#print "{0},{1},{2},WORD".format(image,ftext,fconf)
					oFile.write("{0}|{1}|{2}|WORD\n".format(image,ftext,fconf))
				elif j['Type'] == "LINE":
					ftext = str(j['DetectedText'])
					fconf = str(j['Confidence'])
					#print "{0},{1},{2},LINE".format(image,ftext,fconf)
					oFile.write("{0}|{1}|{2}|LINE\n".format(image,ftext,fconf))
		except:
			print "Oops, skipping.."#+filename
			oFile.write("Error with"+image+"\n")

#Call the Object Detection API
if args.obj:
	oFile=open('obj-'+str(time.time())+'.csv','w')
	for image in image_list:
		try:
			rek_response = detect_labels(image)
			for j in rek_response:
				if 'Name' in j:
					ftext = str(j['Name'])
					fconf = str(j['Confidence'])
					#print "{0},{1},{2}".format(image,ftext,fconf)
					oFile.write("{0}|{1}|{2}\n".format(image,ftext,fconf))
		except:
			print "Oops, skipping.."#+filename
			oFile.write("Error with"+image+"\n")
