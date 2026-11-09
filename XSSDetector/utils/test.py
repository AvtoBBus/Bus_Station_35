import torch
print("torch:", torch.__version__)
print("cuda built:", torch.version.cuda)
print("cuda available:", torch.cuda.is_available())
if torch.cuda.is_available():
    print("device:", torch.cuda.get_device_name(0))
    print("cc:", torch.cuda.get_device_capability(0))      # у 1650 должно быть (7, 5)
    print("vram GB:", torch.cuda.get_device_properties(0).total_memory / 1e9)