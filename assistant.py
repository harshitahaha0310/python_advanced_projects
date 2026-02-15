import pyttsx3
import speech_recognition as sr
import requests
import time
from gtts import gTTS
from playsound import playsound
import os
import threading
import xml.etree.ElementTree as ET

# ================= API KEYS ================= #
WEATHER_API_KEY = "370335d02de4c5bc87ab6bd59e8f58ee"

# ================= INIT ================= #
engine = pyttsx3.init()

def speak(text):
    print("Assistant:", text)
    engine.say(text)
    engine.runAndWait()

def speak_long(text):
    filename = "audio.mp3"
    tts = gTTS(text=text, lang="en")
    tts.save(filename)
    playsound(filename, block=True)
    os.remove(filename)

def listen():
    r = sr.Recognizer()
    with sr.Microphone() as source:
        print("Listening...")
        r.adjust_for_ambient_noise(source, duration=1)
        audio = r.listen(source, phrase_time_limit=5)

    try:
        command = r.recognize_google(audio)
        print("You said:", command)
        return command.lower()
    except:
        return ""

# ================= WEATHER ================= #
def get_weather(city):
    url = f"https://api.openweathermap.org/data/2.5/weather?q={city}&appid={WEATHER_API_KEY}&units=metric"
    data = requests.get(url).json()

    if data.get("cod") == 200:
        temp = data["main"]["temp"]
        desc = data["weather"][0]["description"]
        speak(f"The temperature in {city} is {temp} degree Celsius with {desc}")
    else:
        speak("Sorry, I could not find the city.")

# ================= NEWS (FIXED & RELIABLE) ================= #
def get_news():
    speak("Here are the top news headlines.")
    time.sleep(1)

    url = "https://feeds.bbci.co.uk/news/rss.xml"
    response = requests.get(url)

    root = ET.fromstring(response.content)
    items = root.findall(".//item")[:5]

    for i, item in enumerate(items, start=1):
        headline = item.find("title").text
        print(f"{i}. {headline}")
        speak_long(headline)
        time.sleep(0.3)

    speak("That is all for today.")

# ================= REMINDER ================= #
def reminder_task(seconds, message):
    time.sleep(seconds)
    speak(f"Reminder: {message}")

def set_reminder(command):
    speak("What should I remind you about?")
    message = listen()

    if not message:
        speak("I did not hear the reminder message.")
        return

    speak("In how many seconds?")
    time_input = listen()

    try:
        seconds = int(time_input)
        speak(f"Okay, I will remind you in {seconds} seconds.")
        threading.Thread(target=reminder_task, args=(seconds, message)).start()
    except:
        speak("Sorry, I could not understand the time.")

# ================= COMMAND HANDLER ================= #
def process_command(command):

    if "weather" in command:
        speak("Which city?")
        city = listen()
        if city:
            get_weather(city)
        else:
            speak("I did not hear the city name.")
        return

    if "news" in command:
        get_news()
        return

    if "reminder" in command or "remind me" in command:
        set_reminder(command)
        return

    if "exit" in command or "quit" in command or "stop" in command:
        speak("Goodbye Harshita!")
        exit()

    speak("You can ask for weather, news, or set a reminder.")

# ================= MAIN LOOP ================= #
speak("Hello Harshita. I can tell you the weather, news, or set reminders. Say exit to quit.")
time.sleep(1)

while True:
    command = listen()
    if command:
        process_command(command)
    else:
        speak("I did not hear anything. Please try again.")

