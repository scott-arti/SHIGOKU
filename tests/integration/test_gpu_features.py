#!/usr/bin/env python3
"""
GPU Feature Tests for SHIGOKU Phase 2

Tests:
1. SemanticGrep - Embedding-based fuzzy search
2. VisualReconAgent - LLaVA image analysis (requires llava:7b)
3. ProxyLogAnalyzer LLM Ranking (requires qwen2.5-coder:7b)
"""

import sys
import os
import pytest

# Add project root to path
sys.path.insert(0, "/home/bbb/Documents/App/Shigoku")

@pytest.mark.asyncio
async def test_semantic_grep():
    """Test SemanticGrep with sample HTTP responses"""
    pytest.skip("SemanticGrep is not currently implemented in src/intelligence")


@pytest.mark.asyncio
async def test_visual_recon():
    """Test VisualReconAgent with a sample image"""
    print("\n" + "="*60)
    print("TEST 2: VisualReconAgent (LLaVA Image Analysis)")
    print("="*60)
    
    # Check if ollama is available
    import subprocess
    try:
        result = subprocess.run(["ollama", "list"], capture_output=True, text=True, check=True)
        if "llava" not in result.stdout.lower():
            pytest.skip("LLaVA model not installed")
    except (FileNotFoundError, subprocess.CalledProcessError):
        pytest.skip("Ollama not installed or returned error")

    from src.core.agents.specialized.visual_recon import VisualReconAgent
    
    # Create a simple test image (or use existing screenshot)
    test_image = "/tmp/test_screenshot.png"
    
    # Create a simple test image with PIL if available
    try:
        from PIL import Image, ImageDraw
        img = Image.new('RGB', (400, 300), color='white')
        draw = ImageDraw.Draw(img)
        draw.rectangle([50, 50, 350, 250], outline='black')
        draw.text((150, 100), "Login", fill='black')
        draw.rectangle([100, 150, 300, 180], outline='gray')  # username field
        draw.rectangle([100, 190, 300, 220], outline='gray')  # password field
        draw.rectangle([150, 240, 250, 270], fill='blue')     # login button
        img.save(test_image)
        print(f"\n📷 Created test image: {test_image}")
    except ImportError:
        print("\n⚠️ PIL not available. Looking for existing screenshot...")
        # Try to find any existing PNG in workspace
        import glob
        pngs = glob.glob("/home/bbb/Documents/App/Shigoku/**/*.png", recursive=True)
        if pngs:
            test_image = pngs[0]
            print(f"   Using: {test_image}")
        else:
            pytest.skip("No PNG files found and PIL not available")
    
    print("\n🔍 Analyzing image with LLaVA...")
    agent = VisualReconAgent(model="llava:7b")
    result = await agent.analyze_screenshot(test_image)
    
    print(f"\n📊 Analysis Results:")
    print(f"   Admin Panel: {result.is_admin_panel}")
    print(f"   Error Message: {result.has_error_message}")
    print(f"   Default Page: {result.is_default_page}")
    print(f"   Sensitive Info: {result.has_sensitive_info}")
    print(f"   Confidence: {result.confidence:.2f}")
    print(f"   Description: {result.description[:100]}...")
    
    print("\n✅ VisualReconAgent test completed!")


def test_gpu_accelerator():
    """Test GPU detection and Ollama integration"""
    print("\n" + "="*60)
    print("TEST 3: GPUAccelerator Status")
    print("="*60)
    
    from src.core.gpu_accelerator import GPUAccelerator
    
    gpu = GPUAccelerator()
    status = gpu.get_status()
    
    print(f"\n📊 GPU Status:")
    print(f"   GPU Available: {status['gpu_available']}")
    print(f"   GPU Name: {status['gpu_name']}")
    print(f"   VRAM: {status['gpu_memory_mb']} MB")
    print(f"   Ollama Available: {status['ollama_available']}")
    print(f"   Installed Models: {status['installed_models']}")
    
    print("\n✅ GPUAccelerator test completed!")

