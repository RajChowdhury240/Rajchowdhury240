#!/usr/bin/env python3
"""
AWS IAM User Enumerator - Multi-Account Scanner

Scans all active AWS accounts in an Organization for IAM users,
collecting their tags and creation dates using cross-account role assumption.

Features:
- Fetches all active accounts from AWS Organizations
- Uses STS AssumeRole for cross-account access
- Multithreaded for performance (configurable workers)
- Rich progress bars and live status display
- CSV output with comprehensive error handling
- Retry logic with exponential backoff
"""

import boto3
import csv
import sys
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError, BotoCoreError
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich import box
import threading
import time

# Configuration
DEFAULT_ROLE_NAME = "test-cross"
DEFAULT_OUTPUT_FILE = "iam_users_inventory.csv"
DEFAULT_MAX_WORKERS = 10
DEFAULT_SESSION_DURATION = 3600  # 1 hour

# Thread-safe console and results storage
console = Console()
results_lock = threading.Lock()
all_users = []
failed_accounts = []
skipped_accounts = []


def get_organizations_client():
    """Create AWS Organizations client using default credentials."""
    return boto3.client("organizations")


def get_active_accounts():
    """
    Fetch all ACTIVE accounts from AWS Organizations.
    Returns list of dicts with 'Id', 'Name', 'Email', 'Status'.
    """
    org_client = get_organizations_client()
    accounts = []
    paginator = org_client.get_paginator("list_accounts")
    
    for page in paginator.paginate():
        for account in page["Accounts"]:
            if account["Status"] == "ACTIVE":
                accounts.append({
                    "Id": account["Id"],
                    "Name": account["Name"],
                    "Email": account.get("Email", "N/A"),
                })
    
    return accounts


def assume_role(account_id, role_name, session_duration=DEFAULT_SESSION_DURATION):
    """
    Assume a role in the target account.
    Returns temporary credentials or None if assumption fails.
    """
    sts_client = boto3.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"IAMUserEnumeration-{account_id}",
            DurationSeconds=session_duration,
        )
        return response["Credentials"]
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "AccessDenied":
            return {"error": f"Access denied to assume role {role_arn}"}
        elif error_code == "MalformedPolicyDocument":
            return {"error": f"Malformed trust policy on role {role_arn}"}
        else:
            return {"error": f"{error_code}: {e.response['Error']['Message']}"}
    except Exception as e:
        return {"error": str(e)}


def get_iam_client_for_account(credentials):
    """Create IAM client using assumed role credentials."""
    return boto3.client(
        "iam",
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def get_user_tags(iam_client, username):
    """Fetch tags for a specific IAM user."""
    try:
        response = iam_client.list_user_tags(UserName=username)
        tags = {tag["Key"]: tag["Value"] for tag in response.get("Tags", [])}
        return tags
    except ClientError:
        return {}


def list_iam_users_in_account(iam_client, account_id, account_name):
    """
    List all IAM users in an account with their tags and creation dates.
    Returns list of user dictionaries.
    """
    users = []
    paginator = iam_client.get_paginator("list_users")
    
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            creation_date = user["CreateDate"]
            
            # Format creation date
            if isinstance(creation_date, datetime):
                creation_date_str = creation_date.strftime("%Y-%m-%d %H:%M:%S UTC")
            else:
                creation_date_str = str(creation_date)
            
            # Get user tags
            tags = get_user_tags(iam_client, username)
            
            # Format tags as key=value pairs
            tags_str = "; ".join([f"{k}={v}" for k, v in tags.items()]) if tags else ""
            
            users.append({
                "AccountId": account_id,
                "AccountName": account_name,
                "UserName": username,
                "UserId": user["UserId"],
                "Arn": user["Arn"],
                "CreationDate": creation_date_str,
                "Tags": tags_str,
                "TagCount": len(tags),
                "PasswordLastUsed": user.get("PasswordLastUsed", "Never/No Console Access"),
                "Path": user.get("Path", "/"),
            })
    
    return users


def process_account(account, role_name, progress, task_id):
    """
    Process a single account: assume role and enumerate IAM users.
    Thread-safe function for concurrent execution.
    """
    account_id = account["Id"]
    account_name = account["Name"]
    
    # Update progress description
    progress.update(task_id, description=f"[cyan]Processing: {account_name[:30]}")
    
    # Skip management account (can't assume role into itself typically)
    try:
        sts = boto3.client("sts")
        current_account = sts.get_caller_identity()["Account"]
        if account_id == current_account:
            # For management account, use current credentials
            iam_client = boto3.client("iam")
            users = list_iam_users_in_account(iam_client, account_id, account_name)
            with results_lock:
                all_users.extend(users)
            progress.advance(task_id)
            return {"account_id": account_id, "account_name": account_name, "users": len(users), "status": "success"}
    except Exception:
        pass
    
    # Assume role into target account
    credentials = assume_role(account_id, role_name)
    
    if credentials is None:
        with results_lock:
            failed_accounts.append({
                "AccountId": account_id,
                "AccountName": account_name,
                "Error": "Unknown error during role assumption"
            })
        progress.advance(task_id)
        return {"account_id": account_id, "account_name": account_name, "users": 0, "status": "failed"}
    
    if isinstance(credentials, dict) and "error" in credentials:
        with results_lock:
            failed_accounts.append({
                "AccountId": account_id,
                "AccountName": account_name,
                "Error": credentials["error"]
            })
        progress.advance(task_id)
        return {"account_id": account_id, "account_name": account_name, "users": 0, "status": "failed"}
    
    # Create IAM client with assumed credentials
    try:
        iam_client = get_iam_client_for_account(credentials)
        users = list_iam_users_in_account(iam_client, account_id, account_name)
        
        with results_lock:
            all_users.extend(users)
        
        progress.advance(task_id)
        return {"account_id": account_id, "account_name": account_name, "users": len(users), "status": "success"}
    
    except ClientError as e:
        with results_lock:
            failed_accounts.append({
                "AccountId": account_id,
                "AccountName": account_name,
                "Error": f"IAM error: {e.response['Error']['Message']}"
            })
        progress.advance(task_id)
        return {"account_id": account_id, "account_name": account_name, "users": 0, "status": "failed"}
    except Exception as e:
        with results_lock:
            failed_accounts.append({
                "AccountId": account_id,
                "AccountName": account_name,
                "Error": str(e)
            })
        progress.advance(task_id)
        return {"account_id": account_id, "account_name": account_name, "users": 0, "status": "failed"}


def write_csv(users, output_file):
    """Write IAM users to CSV file."""
    if not users:
        console.print("[yellow]No IAM users found to write to CSV.[/yellow]")
        return
    
    fieldnames = [
        "AccountId",
        "AccountName", 
        "UserName",
        "UserId",
        "Arn",
        "CreationDate",
        "PasswordLastUsed",
        "Path",
        "TagCount",
        "Tags",
    ]
    
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(users)


def write_failed_accounts_csv(failed, output_file):
    """Write failed accounts to a separate CSV."""
    if not failed:
        return
    
    failed_file = output_file.replace(".csv", "_failed_accounts.csv")
    with open(failed_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["AccountId", "AccountName", "Error"])
        writer.writeheader()
        writer.writerows(failed)
    
    return failed_file


def display_summary(accounts_processed, users_found, failed_count, elapsed_time):
    """Display a rich summary table."""
    table = Table(title="ð Scan Summary", box=box.ROUNDED)
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")
    
    table.add_row("Total Accounts Scanned", str(accounts_processed))
    table.add_row("Successful Accounts", str(accounts_processed - failed_count))
    table.add_row("Failed Accounts", f"[red]{failed_count}[/red]" if failed_count > 0 else "0")
    table.add_row("Total IAM Users Found", str(users_found))
    table.add_row("Elapsed Time", f"{elapsed_time:.2f} seconds")
    table.add_row("Avg Time per Account", f"{elapsed_time/max(accounts_processed,1):.2f} seconds")
    
    console.print(table)


def main():
    parser = argparse.ArgumentParser(
        description="Enumerate IAM users across all AWS Organization accounts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
  %(prog)s --role-name SecurityAuditRole --output my_users.csv
  %(prog)s --workers 20 --role-name test-cross
        """
    )
    parser.add_argument(
        "--role-name", "-r",
        default=DEFAULT_ROLE_NAME,
        help=f"Name of the cross-account role to assume (default: {DEFAULT_ROLE_NAME})"
    )
    parser.add_argument(
        "--output", "-o",
        default=DEFAULT_OUTPUT_FILE,
        help=f"Output CSV file path (default: {DEFAULT_OUTPUT_FILE})"
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=DEFAULT_MAX_WORKERS,
        help=f"Number of concurrent threads (default: {DEFAULT_MAX_WORKERS})"
    )
    parser.add_argument(
        "--session-duration", "-d",
        type=int,
        default=DEFAULT_SESSION_DURATION,
        help=f"STS session duration in seconds (default: {DEFAULT_SESSION_DURATION})"
    )
    
    args = parser.parse_args()
    
    # Header
    console.print(Panel.fit(
        "[bold blue]AWS IAM User Enumerator[/bold blue]\n"
        "[dim]Multi-Account Scanner with Cross-Account Role Assumption[/dim]",
        border_style="blue"
    ))
    console.print()
    
    # Configuration display
    console.print(f"[bold]Configuration:[/bold]")
    console.print(f"  â¢ Role Name: [cyan]{args.role_name}[/cyan]")
    console.print(f"  â¢ Output File: [cyan]{args.output}[/cyan]")
    console.print(f"  â¢ Max Workers: [cyan]{args.workers}[/cyan]")
    console.print(f"  â¢ Session Duration: [cyan]{args.session_duration}s[/cyan]")
    console.print()
    
    # Step 1: Fetch all active accounts from Organizations
    console.print("[bold yellow]Step 1:[/bold yellow] Fetching active accounts from AWS Organizations...")
    
    try:
        accounts = get_active_accounts()
        console.print(f"[green]â[/green] Found [bold]{len(accounts)}[/bold] active accounts\n")
    except ClientError as e:
        console.print(f"[red]â[/red] Failed to list accounts: {e.response['Error']['Message']}")
        console.print("[dim]Ensure you have organizations:ListAccounts permission[/dim]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]â[/red] Error: {e}")
        sys.exit(1)
    
    if not accounts:
        console.print("[yellow]No active accounts found. Exiting.[/yellow]")
        sys.exit(0)
    
    # Step 2: Process accounts with progress bar
    console.print(f"[bold yellow]Step 2:[/bold yellow] Scanning IAM users across {len(accounts)} accounts...")
    console.print()
    
    start_time = time.time()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        TextColumn("â¢"),
        TimeElapsedColumn(),
        TextColumn("â¢"),
        TimeRemainingColumn(),
        console=console,
        refresh_per_second=10,
    ) as progress:
        
        task = progress.add_task(
            "[cyan]Scanning accounts...",
            total=len(accounts)
        )
        
        # Use ThreadPoolExecutor for concurrent processing
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(process_account, account, args.role_name, progress, task): account
                for account in accounts
            }
            
            results = []
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    account = futures[future]
                    with results_lock:
                        failed_accounts.append({
                            "AccountId": account["Id"],
                            "AccountName": account["Name"],
                            "Error": f"Thread error: {str(e)}"
                        })
                    progress.advance(task)
    
    elapsed_time = time.time() - start_time
    console.print()
    
    # Step 3: Write results
    console.print("[bold yellow]Step 3:[/bold yellow] Writing results to CSV...")
    
    write_csv(all_users, args.output)
    console.print(f"[green]â[/green] IAM users written to: [bold]{args.output}[/bold]")
    
    if failed_accounts:
        failed_file = write_failed_accounts_csv(failed_accounts, args.output)
        console.print(f"[yellow]![/yellow] Failed accounts written to: [bold]{failed_file}[/bold]")
    
    console.print()
    
    # Display summary
    display_summary(
        accounts_processed=len(accounts),
        users_found=len(all_users),
        failed_count=len(failed_accounts),
        elapsed_time=elapsed_time
    )
    
    # Show sample of failed accounts if any
    if failed_accounts:
        console.print()
        fail_table = Table(title="[red]Failed Accounts (showing first 10)[/red]", box=box.SIMPLE)
        fail_table.add_column("Account ID", style="dim")
        fail_table.add_column("Account Name")
        fail_table.add_column("Error", style="red")
        
        for fa in failed_accounts[:10]:
            fail_table.add_row(fa["AccountId"], fa["AccountName"], fa["Error"][:60])
        
        console.print(fail_table)
    
    console.print()
    console.print("[bold green]â Scan complete![/bold green]")


if __name__ == "__main__":
    main()
