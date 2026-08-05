#!/usr/bin/env python3
from gpiozero.pins.pigpio import PiGPIOFactory
from gpiozero import Servo
from time import sleep

# Use pigpio backend for hardware-timed PWM (no jitter)
factory = PiGPIOFactory()

SERVO_GPIO = 2
servo = Servo(SERVO_GPIO, min_pulse_width=0.0005,
              max_pulse_width=0.0025, pin_factory=factory)

try:
    print("Moving to 0°...")
    servo.min()
    sleep(1)

    print("Moving to 90°...")
    servo.mid()
    sleep(1)

    print("Moving to 180°...")
    servo.max()
    sleep(1)

    print("Back to 90°...")
    servo.mid()
    sleep(1)

    # --- Interactive mode ---
    print("\n─── Interactive Mode ───")
    print("Enter angle (0-180), or 'q' to quit.\n")

    while True:
        user_input = input("Angle> ").strip()
        if user_input.lower() == "q":
            break
        try:
            angle = float(user_input)
            angle = max(0, min(180, angle))
            value = (angle / 90.0) - 1.0
            servo.value = value
            print(f"  → {angle:.1f}°")
        except ValueError:
            print("  Invalid input. Enter 0-180 or 'q'.")

except KeyboardInterrupt:
    print("\nInterrupted.")

finally:
    servo.close()
    print("Servo stopped. GPIO released.")
