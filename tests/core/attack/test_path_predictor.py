import pytest
from src.core.attack.path_predictor import PathPredictor

def test_path_predictor_tier1_katana():
    katana_urls = [
        "http://example.com/assets/images/logo.png",
        "http://example.com/static/docs/manual.pdf",
        "http://example.com/js/main.js",  # Noise
        "http://other.com/assets/img/other.jpg" # Different domain
    ]
    predictor = PathPredictor(katana_urls)
    endpoint = "http://example.com/vulnerabilities/upload/"
    filename = "shell.php"
    
    suggestions = predictor.predict(endpoint, filename)
    
    # Tier 1 suggestions should be present
    tier1 = [s for s in suggestions if s.tier == 1]
    urls = [s.url for s in tier1]
    
    assert "http://example.com/assets/images/shell.php" in urls
    assert "http://example.com/static/docs/shell.php" in urls
    assert "http://example.com/js/shell.php" not in urls # JS is noise
    assert "http://other.com/assets/img/shell.php" not in urls # Different domain

def test_path_predictor_tier2_endpoint():
    predictor = PathPredictor([])
    endpoint = "http://example.com/api/v1/user/profile/upload"
    filename = "shell.php"
    
    suggestions = predictor.predict(endpoint, filename)
    
    # Tier 2 suggestions (parent dirs and common subs)
    tier2 = [s for s in suggestions if s.tier == 2]
    urls = [s.url for s in tier2]
    
    assert "http://example.com/api/v1/user/profile/shell.php" in urls
    assert "http://example.com/api/v1/user/shell.php" in urls
    assert "http://example.com/api/shell.php" in urls
    assert "http://example.com/api/v1/user/profile/uploads/shell.php" in urls

def test_path_predictor_scoring_similarity():
    # エンドポイントに近いディレクトリほど高スコアになるか検証
    katana_urls = [
        "http://example.com/users/profile/images/avatar.jpg", # Close
        "http://example.com/archive/2020/old.jpg",           # Far
    ]
    predictor = PathPredictor(katana_urls)
    endpoint = "http://example.com/users/profile/upload"
    filename = "shell.php"
    
    suggestions = predictor.predict(endpoint, filename)
    
    # Close one should have higher score
    close_path = "http://example.com/users/profile/images/shell.php"
    far_path = "http://example.com/archive/2020/shell.php"
    
    close_score = next(s.score for s in suggestions if s.url == close_path)
    far_score = next(s.score for s in suggestions if s.url == far_path)
    
    assert close_score > far_score

def test_path_predictor_tier3_fallback():
    predictor = PathPredictor([])
    endpoint = "http://example.com/"
    filename = "shell.php"
    
    suggestions = predictor.predict(endpoint, filename)
    
    # Tier 3 fallback (or Tier 2 if endpoint is root)
    urls = [s.url for s in suggestions]
    
    assert "http://example.com/uploads/shell.php" in urls
    assert "http://example.com/shell.php" in urls
