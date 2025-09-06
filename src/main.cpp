#include"db_manager.h"
#include"password_manager.h"

void RegisterUser(PasswordManager &pm){
    std::string username,password;
    std::cout<<"<======Create Account ======>"<<std::endl;
    std::cout<<"Create Your Username :";
    std::cin>>username;
    std::cout<<"\nCreate a Password :";
    std::cin>>password;
    if(pm.registeruser(username,password)){
        std::cout<<"Registered successfully"<<std::endl;

    }else{
        std::cout<<"Unable to register!"<<std::endl;
        return;
    }
}

void loginUser(PasswordManager &pm){
std::string username,password;
std::cout<<"Enter Your Username :";
std::cin>>username;
std::cout<<"\nEnter Your Password :";
std::cin>> password;
if(pm.loginUser(username,password)){
    std::cout<<"Login successful."<<std::endl;
}else{
    std::cout<<"Wrong Password or user not exist!"<<std::endl;
    return;
}
}
void addInfo(PasswordManager &pm){
std::string website,username,password;
std::cout<<"Enter Website name :";
std::cin>>website;
std::cout<<"\nEnter Username :";
std::cin>>username;
std::cout<<"\nEnter Password :";
std::cin>>password;
pm.addPassword(website,username,password);
}

void UpdateInfo(PasswordManager &pm){
std::string website,username,password;
std::cout<<"Enter Website name which want to update details :";
std::cin>>website;
std::cout<<"\nEnter NewUsername :";
std::cin>>username;
std::cout<<"\nEnter NewPassword :";
std::cin>>password;
pm.UpdateInfo(website,username,password);
}

void DeleteInfo(PasswordManager &pm){
    std::string website;
    std::cout<<"Enter Website name which want to delete :";
    std::cin>>website;
    pm.deleteInfo(website);

}

void ReadInfo(PasswordManager &pm){
    std::string website;
    std::cout<<"Enter Website name :";
    std::cin>>website; 
    pm.retrievePasswords(website);  

}
void viewAll(PasswordManager &pm){
    pm.viewAllPasswords();
}

void UpdateMasterPassword(){

}

void ShowMenu() {
    std::cout << "\n--- Password Manager Menu ---\n";
    std::cout << "1. Create New Account.\n";
    std::cout << "2. Login in Your Account\n";
    std::cout << "3. Add Credentials\n";
    std::cout << "4. Find Credentials\n";
    std::cout << "5. Update Credentials\n";
    std::cout << "6. Delete Credentials\n";
    std::cout << "7. View All Credentials\n";
    std::cout << "8. Change Master Password\n";
    std::cout << "0. Exit\n";
    std::cout << "Enter Your Choice: ";
}

void RunManager(PasswordManager &pm) {
    int choice;
    do {
        ShowMenu();
        std::cin >> choice;

        switch (choice) {
            case 1: RegisterUser(pm); break;
            case 2: loginUser(pm); break;
            case 3: addInfo(pm); break;
            case 4: ReadInfo(pm); break;
            case 5: UpdateInfo(pm); break;
            case 6: DeleteInfo(pm); break;
            case 7: viewAll(pm); break;
        //  case 8: ChangeMasterPassword(manager,DerivedKey); break;
            case 0: std::cout << "Exiting...\n";  break;
            default: std::cout << "Invalid choice, try again!\n"; break;
        }
    } while (choice != 0);
}
int main(){
DBManager db("config/db_config.json");
PasswordManager pm(&db);
if(!db.connect()){
    std::cout<<"there is no connction with database."<<std::endl;
}else{
    std::cout<<"connected to Database."<<std::endl;
    RunManager(pm);
    return 0;
}

}