#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Scanner Launcher

Choose between CLI and GUI modes for the network scanner.
"""

import sys
import os

def show_menu():
    print(" Network Security Scanner")
    print("=" * 40)
    print("Choose your interface:")
    print("1. CLI Mode (Command Line)")
    print("2. GUI Mode (Graphical)")
    print("3. Exit")
    print("=" * 40)

def main():
    while True:
        show_menu()
        choice = input("Enter your choice (1-3): ").strip()
        
        if choice == "1":
            print("  Starting CLI mode...")
            os.system("python script.py")
        elif choice == "2":
            print("  Starting GUI mode...")
            os.system("python scanner_gui.py")
        elif choice == "3":
            print(" Goodbye!")
            sys.exit(0)
        else:
            print(" Invalid choice. Please enter 1, 2, or 3.")
            input("Press Enter to continue...")

if __name__ == "__main__":
    main() 