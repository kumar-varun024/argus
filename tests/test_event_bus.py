from argus.core.event_bus import EventBus


def on_host_found(host):
    print(f"Host discovered: {host}")


bus = EventBus()

bus.subscribe("HostFound", on_host_found)

bus.publish("HostFound", "api.twilio.com")
