#!/usr/bin/env python3
"""
Caido Log Processing Pipeline

CaidoImporter と TaggingFilter を連携させ、
Caido の生ログから分析用データを一気通貫で生成するスクリプト。
"""

import argparse
import logging
import json
import sys
from pathlib import Path
from datetime import datetime

# Adjust path to import modules
sys.path.append(str(Path(__file__).resolve().parent.parent.parent.parent))

from src.tools.custom.caido_importer import CaidoImporter
from src.core.intel.tagging_filter import TaggingFilter

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("CaidoPipeline")

def main():
    parser = argparse.ArgumentParser(description="Caido ログ処理パイプライン (Import -> Mask -> Tag)")
    parser.add_argument("-i", "--input", required=True, help="Caido JSON エクスポートファイルのパス")
    parser.add_argument("-o", "--output-dir", default=None, help="出力ディレクトリ（未指定時: workspace/projects/<project>/scans/raw/caido）")
    parser.add_argument("-p", "--project", default="unknown", help="プロジェクト名")
    parser.add_argument("--keep-intermediate", action="store_true", help="中間ファイル（マスク済みJSON）を保持する")
    
    args = parser.parse_args()
    
    input_path = Path(args.input)
    output_dir = Path(args.output_dir) if args.output_dir else Path("workspace") / "projects" / args.project / "scans" / "raw" / "caido"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Import & Mask
    logger.info("=== Phase 1: Importing & Masking ===")
    importer = CaidoImporter()
    try:
        processed_data = importer.import_file(str(input_path))
    except Exception as e:
        logger.error(f"Import failed: {e}")
        return
    
    if not processed_data:
        logger.warning("No data processed. Exiting.")
        return

    # Save intermediate file
    date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    intermediate_file = output_dir / f"masked_import_{date_str}.json"
    
    with open(intermediate_file, 'w', encoding='utf-8') as f:
        json.dump(processed_data, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Intermediate masked data saved to: {intermediate_file}")
    
    # 2. Tagging
    logger.info("=== Phase 2: Tagging & Filtering ===")
    tagger = TaggingFilter(project_name=args.project)
    
    try:
        stats = tagger.process_file(str(intermediate_file), str(output_dir))
    except Exception as e:
        logger.error(f"Tagging failed: {e}")
        return
        
    # Cleaning up
    if not args.keep_intermediate:
        intermediate_file.unlink()
        logger.info("Intermediate file removed.")
    
    # Summary
    print("\n✅ Pipeline Completed!")
    print(f"Output Directory: {output_dir}")
    print("Statistics:")
    for tag, count in stats.items():
        if count > 0:
            print(f"  - {tag}: {count}")

if __name__ == "__main__":
    main()
