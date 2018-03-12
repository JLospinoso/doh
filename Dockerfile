FROM quay.io/jlospinoso/cppbuild:v1.4.0
RUN apt update && apt upgrade -y

RUN mkdir doh
WORKDIR doh

COPY *.h *.hpp *.cpp CMakeLists.txt ./
RUN mkdir build
WORKDIR build
RUN cmake ..
RUN make
COPY block host ./
ENTRYPOINT ["/doh/build/doh"]
