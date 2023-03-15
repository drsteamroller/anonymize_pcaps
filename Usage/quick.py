


out = "config switch-controller managed-switch\nedit <FSW-ID>\nconfig ports\n"

for x in range(1, 55):
	out += f"edit port{x}\nset ptp-policy default\nn\n"

out += "end\n"
print(out)