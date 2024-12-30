import os
import configparser
import boto3
import sys
from botocore.exceptions import ProfileNotFound, ClientError

class AwsMfaManager:
    def __init__(self):
        self.aws_folder = os.path.expanduser('~/.aws')
        self.credentials_path = os.path.join(self.aws_folder, 'credentials')
        self.config_path = os.path.join(self.aws_folder, 'config')
        
        # Tạo thư mục .aws và các file cấu hình nếu chưa tồn tại
        if not os.path.exists(self.aws_folder):
            os.makedirs(self.aws_folder)
            print(f"Đã tạo thư mục {self.aws_folder}")

        if not os.path.exists(self.credentials_path):
            with open(self.credentials_path, 'w') as f:
                f.write("[default]\n")
            print(f"Đã tạo file {self.credentials_path}")

        if not os.path.exists(self.config_path):
            with open(self.config_path, 'w') as f:
                f.write("[default]\n")
            print(f"Đã tạo file {self.config_path}")

    def check_credentials(self, profile):
        """Kiểm tra thông tin xác thực của profile"""
        config = configparser.ConfigParser()
        if not os.path.exists(self.credentials_path):
            return False, "File credentials không tồn tại"

        config.read(self.credentials_path)
        if profile not in config:
            return False, f"Profile '{profile}' không tồn tại trong file credentials"

        required_keys = ['aws_access_key_id', 'aws_secret_access_key']
        missing_keys = [key for key in required_keys if key not in config[profile]]
        
        if missing_keys:
            return False, f"Thiếu thông tin xác thực: {', '.join(missing_keys)}"

        return True, "OK"

    def setup_credentials(self, profile):
        """Thiết lập thông tin xác thực cơ bản cho profile"""
        print(f"\nCần thiết lập thông tin xác thực cho profile '{profile}'")
        access_key = input("Nhập AWS Access Key ID: ").strip()
        secret_key = input("Nhập AWS Secret Access Key: ").strip()

        config = configparser.ConfigParser()
        if os.path.exists(self.credentials_path):
            config.read(self.credentials_path)

        if profile not in config:
            config[profile] = {}

        config[profile]['aws_access_key_id'] = access_key
        config[profile]['aws_secret_access_key'] = secret_key

        with open(self.credentials_path, 'w') as f:
            config.write(f)
        
        print(f"Đã lưu thông tin xác thực cho profile '{profile}'")

    def verify_aws_connection(self, profile):
        """Kiểm tra kết nối AWS với thông tin xác thực"""
        try:
            session = boto3.Session(profile_name=profile)
            sts = session.client('sts')
            sts.get_caller_identity()
            return True
        except (ProfileNotFound, ClientError) as e:
            return False

    def get_profiles_with_mfa(self):
        """Lấy danh sách các profile đã cấu hình MFA"""
        if not os.path.exists(self.config_path):
            return []

        config = configparser.ConfigParser()
        config.read(self.config_path)
        
        profiles = []
        for section in config.sections():
            profile_name = section.replace('profile ', '') if section.startswith('profile ') else section
            if config.has_option(section, 'mfa_serial'):
                profiles.append(profile_name)
        
        return profiles

    def get_mfa_serial(self, profile):
        """Lấy MFA Serial ARN cho profile đã chọn"""
        if not os.path.exists(self.config_path):
            return None

        config = configparser.ConfigParser()
        config.read(self.config_path)
        
        section = f'profile {profile}' if profile != 'default' else 'default'
        
        if section in config and 'mfa_serial' in config[section]:
            return config[section]['mfa_serial']
        return None

    def save_mfa_serial(self, profile, mfa_serial):
        """Lưu MFA Serial ARN vào file config"""
        config = configparser.ConfigParser()
        if os.path.exists(self.config_path):
            config.read(self.config_path)

        section = f'profile {profile}' if profile != 'default' else 'default'
        
        if section not in config:
            config[section] = {}
        
        config[section]['mfa_serial'] = mfa_serial
        
        with open(self.config_path, 'w') as f:
            config.write(f)

    def update_credentials(self, profile, session_token):
        """Cập nhật credentials với session token mới"""
        config = configparser.ConfigParser()
        if os.path.exists(self.credentials_path):
            config.read(self.credentials_path)

        # Backup thông tin xác thực dài hạn
        if profile in config:
            long_term = {
                'aws_access_key_id': config[profile]['aws_access_key_id'],
                'aws_secret_access_key': config[profile]['aws_secret_access_key']
            }
            
            # Tạo section long-term nếu chưa có
            long_term_profile = f"{profile}-long-term"
            if long_term_profile not in config:
                config[long_term_profile] = long_term

        # Cập nhật session token
        if profile not in config:
            config[profile] = {}

        config[profile]['aws_access_key_id'] = session_token['Credentials']['AccessKeyId']
        config[profile]['aws_secret_access_key'] = session_token['Credentials']['SecretAccessKey']
        config[profile]['aws_session_token'] = session_token['Credentials']['SessionToken']

        with open(self.credentials_path, 'w') as f:
            config.write(f)
            
    def get_long_term_credentials(self, profile):
        """Lấy long-term credentials từ profile"""
        config = configparser.ConfigParser()
        if not os.path.exists(self.credentials_path):
            return None, None

        config.read(self.credentials_path)
        long_term_profile = f"{profile}-long-term"

        if long_term_profile in config:
            return (
                config[long_term_profile]['aws_access_key_id'],
                config[long_term_profile]['aws_secret_access_key']
            )
        elif profile in config:
            # Nếu không có long-term profile, kiểm tra xem profile hiện tại có session token không
            if 'aws_session_token' not in config[profile]:
                # Nếu không có session token, có thể đây là long-term credentials
                return (
                    config[profile]['aws_access_key_id'],
                    config[profile]['aws_secret_access_key']
                )
        return None, None

    def get_session_token(self, profile, mfa_serial, token_code):
        """Lấy session token từ AWS STS sử dụng long-term credentials"""
        try:
            # Lấy long-term credentials
            access_key, secret_key = self.get_long_term_credentials(profile)
            
            if not access_key or not secret_key:
                print(f"\nKhông tìm thấy long-term credentials cho profile '{profile}'")
                print("Vui lòng nhập lại thông tin xác thực dài hạn:")
                access_key = input("AWS Access Key ID: ").strip()
                secret_key = input("AWS Secret Access Key: ").strip()
                
                # Lưu long-term credentials
                config = configparser.ConfigParser()
                if os.path.exists(self.credentials_path):
                    config.read(self.credentials_path)
                
                long_term_profile = f"{profile}-long-term"
                config[long_term_profile] = {
                    'aws_access_key_id': access_key,
                    'aws_secret_access_key': secret_key
                }
                
                with open(self.credentials_path, 'w') as f:
                    config.write(f)

            # Tạo session với long-term credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )
            
            sts_client = session.client('sts')
            response = sts_client.get_session_token(
                SerialNumber=mfa_serial,
                TokenCode=token_code,
                DurationSeconds=28800  # 8 giờ
            )
            return response
        except Exception as e:
            print(f"Lỗi khi lấy session token: {str(e)}")
            sys.exit(1)

def main():
    mfa_manager = AwsMfaManager()
    
    # Hiển thị danh sách profile đã cấu hình
    profiles = mfa_manager.get_profiles_with_mfa()
    print("\nDanh sách profile đã cấu hình MFA:")
    if not profiles:
        print("Chưa có profile nào được cấu hình MFA")
    else:
        for profile in profiles:
            print(f" - {profile}")
    
    # Yêu cầu người dùng chọn profile
    selected_profile = input("\nNhập tên profile muốn sử dụng: ").strip()
    
    # Kiểm tra và thiết lập thông tin xác thực nếu cần
    creds_ok, message = mfa_manager.check_credentials(selected_profile)
    if not creds_ok:
        print(f"\nKiểm tra thông tin xác thực: {message}")
        mfa_manager.setup_credentials(selected_profile)
    
    # Xác minh kết nối AWS
    if not mfa_manager.verify_aws_connection(selected_profile):
        print("\nKhông thể kết nối tới AWS với thông tin xác thực hiện tại.")
        print("Vui lòng kiểm tra lại Access Key và Secret Key.")
        sys.exit(1)
    
    # Kiểm tra và lấy MFA Serial
    mfa_serial = mfa_manager.get_mfa_serial(selected_profile)
    if not mfa_serial:
        print(f"\nProfile '{selected_profile}' chưa được cấu hình MFA Serial.")
        mfa_serial = input("Nhập MFA Serial ARN (dạng arn:aws:iam::<account-id>:mfa/<username>): ").strip()
        mfa_manager.save_mfa_serial(selected_profile, mfa_serial)
        print(f"Đã lưu cấu hình MFA Serial cho profile '{selected_profile}'")
    
    # Yêu cầu nhập MFA code
    mfa_code = input(f"\nNhập MFA code cho profile '{selected_profile}': ").strip()
    
    # Lấy và lưu session token
    try:
        session_token = mfa_manager.get_session_token(selected_profile, mfa_serial, mfa_code)
        mfa_manager.update_credentials(selected_profile, session_token)
        
        print(f"\nĐã cập nhật thành công AWS credentials cho profile '{selected_profile}'")
        print(f"Thời gian hết hạn: {session_token['Credentials']['Expiration']}")
        print(f"\nĐể sử dụng profile này, thêm '--profile {selected_profile}' vào câu lệnh AWS CLI")
        print(f"Ví dụ: aws s3 ls --profile {selected_profile}")
    except Exception as e:
        print(f"\nLỗi: {str(e)}")
        print("Vui lòng kiểm tra lại thông tin xác thực và MFA code.")
        sys.exit(1)

if __name__ == "__main__":
    main()