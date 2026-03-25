import json
import dspy

# Test 1: Can we configure DSPy/Ollama at all?
print("[test] Configuring Ollama LM...")
try:
    lm = dspy.LM(
        "ollama_chat/llama3",
        api_base="http://localhost:11434",
        api_key="ollama",
        timeout=10,
    )
    dspy.configure(lm=lm)
    print("✓ LM configured OK")
except Exception as e:
    print(f"✗ LM config failed: {e}")
    exit(1)

# Test 2: Can we call a simple DSPy signature?
print("\n[test] Creating simple test signature...")

class SimpleTest(dspy.Signature):
    question: str = dspy.InputField(desc="A question")
    answer: str = dspy.OutputField(desc="A short answer")

try:
    predict = dspy.Predict(SimpleTest)
    print("✓ Signature created OK")
except Exception as e:
    print(f"✗ Signature creation failed: {e}")
    exit(1)

# Test 3: Can we actually call the model?
print("\n[test] Calling model with timeout=10s...")
try:
    result = predict(question="What is 2+2?")
    print(f"✓ Model returned: {result.answer}")
except Exception as e:
    print(f"✗ Model call failed: {e}")
    import traceback
    traceback.print_exc()
    exit(1)

print("\n✓ All tests passed - Ollama/DSPy is working!")
