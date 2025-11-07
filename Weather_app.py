import requests

API_KEY = "YOUR_API_KEY_HERE"  
BASE_URL = "https://api.openweathermap.org/data/2.5/weather"

def get_weather(city):
    params = {
        "q": city,
        "appid": API_KEY,
        "units": "metric"
    }
    response = requests.get(BASE_URL, params=params)
    data = response.json()

    if response.status_code == 200:
        print(f"\n🌤️ Weather in {data['name']}, {data['sys']['country']}")
        print(f"🌡️ Temperature: {data['main']['temp']}°C")
        print(f"💧 Humidity: {data['main']['humidity']}%")
        print(f"☁️ Condition: {data['weather'][0]['description'].title()}")
    else:
        print(f"\n❌ Error: {data['message'].title()}")

if __name__ == "__main__":
    print("=== 🌦️ Simple Weather App ===")
    city = input("Enter city name: ").strip()
    get_weather(city)


