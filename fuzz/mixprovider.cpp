#include "mixprovider.h"
#include "fileexception.h"
mixprovider::mixprovider(const std::map<int,std::string> &files)
        : m_files(files)
{
        for(std::map<int, std::string>::iterator it=m_files.begin(); it != m_files.end(); it++) {
                std::ifstream in(m_files[it->first], std::ios::in | std::ios::binary);

                if(!in) {
                        throw fileexception(fileexception::notopened);
                }
                std::string str;
                while(getline(in,str)) {
                        m_raw_data[it->first].push_back(str);
                }
                in.close();
        }
}

unsigned int mixprovider::get_count(){
        unsigned int size=0;
        for(map_it it=m_raw_data.begin(); it != m_raw_data.end(); it++) {
                size += m_raw_data[it->first].size();
        }
        return size;
}

std::string mixprovider::get_data(unsigned int index){

        std::string data;

        if(get_count() < index) {
                throw fileexception(fileexception::overindex);
        }

        data = create_data_for_index(index);

        return data;
}

std::string mixprovider::create_data_for_index(unsigned int index){

        std::string for_combine[m_raw_data.size()];

        map_it it = get_index_element(index,for_combine);
        get_other_elements(it,for_combine);

        std::string data;
        data = for_combine[METHOD] + for_combine[URI] + for_combine[VERSION];
        for(unsigned int j =3; j < m_raw_data.size(); j++) {
                data += "\n";
                data += for_combine[j];
        }
        data += "\r\n\r\n";

        return data;
}

map_it mixprovider::get_index_element(unsigned int index,std::string *for_combine){
        int sub;
        int tmp = (int)index;
        map_it it;
        for(it=m_raw_data.begin(); it != m_raw_data.end(); it++) {
                unsigned int size=m_raw_data[it->first].size();
                sub = tmp - size;
                if(sub < 0) {
                        for_combine[it->first]=m_raw_data[it->first][tmp];
                        break;
                }else{
                        tmp = sub;
                }
        }

        return it;
}

void mixprovider::get_other_elements(map_it it,std::string *for_combine){

        for(map_it it2=m_raw_data.begin(); it2 != m_raw_data.end(); it2++) {
                if(it->first != it2->first) {
                        for_combine[it2->first] = m_raw_data[it2->first][0];
                }
        }

}
