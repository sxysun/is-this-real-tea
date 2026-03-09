"""CLI entry point: python -m dstack_audit <repo_url> <website_url>"""
import argparse
import sys

from .pipeline import run_audit
from .report import generate_report


def main():
    parser = argparse.ArgumentParser(
        prog='dstack-audit',
        description='Audit a dstack TEE application for DevProof (ERC-733) compliance.',
    )
    parser.add_argument('repo_url', help='GitHub repository URL')
    parser.add_argument('website_url', help='Phala Cloud app URL')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Print progress to stderr')
    parser.add_argument('-o', '--output', help='Write report to file instead of stdout')

    args = parser.parse_args()

    report = run_audit(args.repo_url, args.website_url, verbose=args.verbose)
    markdown = generate_report(report)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(markdown)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(markdown)

    # Exit with non-zero if critical findings
    from .models import Severity
    critical_count = sum(1 for f in report.findings if f.severity == Severity.CRITICAL)
    sys.exit(1 if critical_count > 0 else 0)


if __name__ == '__main__':
    main()
